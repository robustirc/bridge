// bridge bridges between IRC clients (RFC1459) and RobustIRC servers.
//
// Bridge instances are supposed to be long-running, and ideally as close to the
// IRC client as possible, e.g. on the same machine. When running on the same
// machine, there should not be any network problems between the IRC client and
// the bridge. Network problems between the bridge and a RobustIRC network are
// handled transparently.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/robustirc/bridge/robustsession"

	"github.com/sorcix/irc"

	// Necessary on go1.0.2 (debian wheezy) to make crypto/tls work with the
	// certificates on robustirc.net (and possibly others).
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var (
	network = flag.String("network",
		"",
		`DNS name to connect to (e.g. "robustirc.net"). The _robustirc._tcp SRV record must be present.`)

	listen = flag.String("listen",
		"localhost:6667",
		"comma-separated list of host:port tuples to listen on for IRC connections. You must also specify -network for -listen to work (or use SOCKS instead)")

	socks = flag.String("socks",
		"localhost:1080",
		"host:port to listen on for SOCKS5 connections")

	httpAddress = flag.String("http",
		"",
		"(for debugging) host:port to listen on for HTTP connections, exposing /debug/pprof")

	tlsCertPath = flag.String("tls_cert_path",
		"",
		"Path to a .pem file containing the TLS certificate. If unspecified, TLS is not used.")

	tlsKeyPath = flag.String("tls_key_path",
		"",
		"Path to a .pem file containing the TLS private key. If unspecified, TLS is not used.")

	tlsCAFile = flag.String("tls_ca_file",
		"",
		"Use the specified file as trusted CA instead of the system CAs. Useful for testing.")

	motdPath = flag.String("motd_path",
		"/usr/share/robustirc/bridge-motd.txt",
		"Path to a text file containing the message of the day (MOTD) to prefix to the network MOTD.")

	authPath = flag.String("bridge_auth",
		"",
		"Path to a text file containing one network:secretkey pair per line to authenticate this bridge against the configured RobustIRC networks.")

	version = flag.Bool("version",
		false,
		"Print version and exit.")
)

// TODO(secure): persistent state:
// - the last known server(s) in the network. added to *servers
// - for resuming sessions (later): the last seen message id, perhaps setup messages (JOINs, MODEs, …)
// for hosted mode, this state is stored per-nickname, ideally encrypted with password

// prefixMotd takes an irc.MOTD message from the server and prefixes it with
// our own MOTD. E.g., it takes:
//   :robustirc.net 372 sECuRE :- First line of MOTD\r\n
// and turns that into:
//   :robustirc.net 372 sECuRE :- First line of bridge MOTD\r\n
//   :robustirc.net 372 sECuRE :- Thanks for using this bridge! Enjoy!\r\n
//   :robustirc.net 372 sECuRE :- First line of MOTD\r\n
func prefixMotd(msg string) string {
	// The user chose to not inject a MOTD.
	if *motdPath == "" {
		return msg
	}

	sep := strings.Index(msg[1:], ":")
	if sep == -1 {
		return msg
	}

	prefix := msg[:sep+2] + "- "

	f, err := os.Open(*motdPath)
	if err != nil {
		log.Printf("Cannot inject MOTD: %v\n", err)
		return msg
	}
	defer f.Close()

	var injected []string

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Cannot inject MOTD: %v\n", err)
			return msg
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		injected = append(injected, prefix+line)
	}

	return strings.Join(injected, "\r\n") + "\r\n" + msg
}

type bridge struct {
	network string
	auth    string
}

func getAuth(path, network string) (string, error) {
	if path == "" {
		return "", nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Mode()&007 != 0 {
		return "", fmt.Errorf("-bridge_auth=%q has insecure permissions %o, fix with chmod o-rwx %q", path, st.Mode(), path)
	}
	authBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	networkPrefix := network + ":"
	for _, line := range strings.Split(string(authBytes), "\n") {
		if strings.HasPrefix(line, networkPrefix) {
			auth := line[len(networkPrefix):]
			if got, want := len(auth), 32; got < want {
				return "", fmt.Errorf("Authentication data for network %q in %q is too short: got %d, want at least %d bytes", network, path, got, want)
			}
			return auth, nil
		}
	}
	return "", nil
}

func newBridge(network string) *bridge {
	auth, err := getAuth(*authPath, network)
	if err != nil {
		log.Printf("Could not get authentication data for network %q: %v", network, err)
	}
	return &bridge{
		network: network,
		auth:    auth,
	}
}

type ircsession struct {
	Messages chan irc.Message
	Errors   chan error

	conn    *irc.Conn
	rawConn net.Conn
}

func newIrcsession(conn net.Conn) *ircsession {
	s := &ircsession{
		Messages: make(chan irc.Message),
		Errors:   make(chan error),
		conn:     irc.NewConn(conn),
		rawConn:  conn,
	}
	go s.getMessages()
	return s
}

func (s *ircsession) Send(msg []byte) error {
	if _, err := s.conn.Write(msg); err != nil {
		return err
	}
	return nil
}

func (s *ircsession) Delete(killmsg string) error {
	defer s.conn.Close()
	// Read all remaining values to ensure nobody is blocked on sending.
	defer func() {
		go func() {
			for _ = range s.Messages {
			}
		}()
		go func() {
			for _ = range s.Errors {
			}
		}()
	}()

	if killmsg != "" {
		return s.conn.Encode(&irc.Message{
			Command:  "ERROR",
			Trailing: killmsg,
		})
	}

	return nil
}

func (s *ircsession) getMessages() {
	defer close(s.Messages)
	defer close(s.Errors)

	// Read the first byte. If it’s 4 or 5, this is likely SOCKS
	first := make([]byte, 1)
	if _, err := s.rawConn.Read(first); err != nil {
		s.Errors <- err
		return
	}

	// %x04 or %x05 as the first byte is both invalid according to RFC2812
	// section 2.3.1. Valid characters are ":" (%x3A) or %x30-39 (0-9) or
	// %x41-5A / %x61-7A (A-Z / a-z).
	// So we can just close the connection here, and also log that the user is
	// most likely trying to use SOCKS on the wrong port.
	//
	// TODO(secure): With some refactoring, we might even just handle the SOCKS
	// connection properly.
	if first[0] == 4 || first[0] == 5 {
		log.Printf("Read 0x%02x as first byte, which looks like a SOCKS version number. Please connect to %q instead of %q.\n", first[0], *socks, *listen)
		s.Errors <- fmt.Errorf("Read 0x%02x (SOCKS version?) as first byte on an IRC connection", first[0])
		return
	}

	line := []byte{first[0]}

	for first[0] != '\n' {
		if _, err := s.rawConn.Read(first); err != nil {
			s.Errors <- err
			return
		}
		line = append(line, first[0])
	}

	ircmsg := irc.ParseMessage(string(line))
	if ircmsg != nil {
		s.Messages <- *ircmsg
	}

	for {
		ircmsg, err := s.conn.Decode()
		if err != nil {
			s.Errors <- err
			return
		}
		// Skip invalid lines (to prevent nil pointer dereferences).
		if ircmsg == nil {
			continue
		}
		s.Messages <- *ircmsg
	}
}

func (p *bridge) handleIRC(conn net.Conn) {
	var quitmsg, killmsg string
	var waitingForPingReply bool

	ircSession := newIrcsession(conn)

	defer func() {
		log.Printf("Terminating IRC connection from %s. killmsg=%q\n", conn.RemoteAddr(), killmsg)
		if err := ircSession.Delete(killmsg); err != nil {
			log.Printf("Could not properly delete IRC session: %v\n", err)
		}
		// The separator makes it easier to read logs when the client is
		// reconnecting in a loop (which is the most common situation in which
		// you’re interested in the logs at all).
		log.Printf("\n")
	}()

	robustSession, err := robustsession.Create(p.network, *tlsCAFile)
	if err != nil {
		killmsg = fmt.Sprintf("Could not create RobustIRC session: %v", err)
		return
	}

	robustSession.BridgeAuth = p.auth
	robustSession.ForwardedFor = conn.RemoteAddr().String()

	log.Printf("[session %s] Created RobustSession for client %s\n", robustSession.SessionId(), conn.RemoteAddr())

	defer func() {
		log.Printf("[session %s] Deleting RobustSession. quitmsg=%q\n", robustSession.SessionId(), quitmsg)
		if err := robustSession.Delete(quitmsg); err != nil {
			log.Printf("Could not properly delete RobustIRC session: %v\n", err)
		}
	}()

	var sendIRC, sendRobust []byte

	keepalivePong := ":" + robustSession.IrcPrefix.String() + " PONG keepalive"
	// like keepalivePong, but with the trailing parameter encoded using the
	// prefix separator (as sorcix/irc.v2 does, well in accordance with
	// RFC1459).
	keepalivePongTrailing := ":" + robustSession.IrcPrefix.String() + " PONG :keepalive"
	motdPrefix := ":" + robustSession.IrcPrefix.String() + " 372 "
	welcomePrefix := ":" + robustSession.IrcPrefix.String() + " 001 "
	welcomed := false
	motdInjected := false

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	keepaliveToNetwork := time.After(1 * time.Minute)
	keepaliveToClient := time.After(1 * time.Minute)
	for {
		// These two variables contain the messages to be sent to IRC/RobustIRC
		// from the previous iteration of the state machine. That way, there is
		// only one place where the error handling happens.
		if sendIRC != nil {
			if err := ircSession.Send(sendIRC); err != nil {
				quitmsg = fmt.Sprintf("Bridge: Send to IRC client: %v", err)
				return
			}
			keepaliveToClient = time.After(1 * time.Minute)
			sendIRC = nil
		}
		if sendRobust != nil {
			if err := robustSession.PostMessage(string(sendRobust)); err != nil {
				killmsg = fmt.Sprintf("Could not post message to RobustIRC: %v", err)
				return
			}
			keepaliveToNetwork = time.After(1 * time.Minute)
			sendRobust = nil
		}

		select {
		case sig := <-signalChan:
			killmsg = fmt.Sprintf("Bridge exiting upon receiving signal (%v)", sig)
			quitmsg = killmsg
			return

		case msg := <-robustSession.Messages:
			// Inject the bridge’s message of the day.
			if !motdInjected && strings.HasPrefix(msg, motdPrefix) {
				sendIRC = []byte(prefixMotd(msg))
				break
			}
			// For debugging purposes, print a log message when the client successfully logs into IRC.
			if !welcomed && strings.HasPrefix(msg, welcomePrefix) {
				log.Printf("[session %s] Successfully logged into IRC.\n", robustSession.SessionId())
				welcomed = true
			}
			if msg == keepalivePong || msg == keepalivePongTrailing {
				break
			}
			sendIRC = []byte(msg)

		case err := <-robustSession.Errors:
			killmsg = fmt.Sprintf("RobustIRC session error: %v", err)
			return

		case ircmsg := <-ircSession.Messages:
			switch strings.ToUpper(ircmsg.Command) {
			case irc.PONG:
				waitingForPingReply = false

			case irc.PING:
				sendIRC = (&irc.Message{
					Prefix:   robustSession.IrcPrefix,
					Command:  irc.PONG,
					Params:   ircmsg.Params,
					Trailing: ircmsg.Trailing,
				}).Bytes()

			case irc.QUIT:
				// Only interpret this as QUIT when it’s coming directly as a
				// command, not as a server-to-server message.
				if ircmsg.Prefix == nil {
					quitmsg = ircmsg.Trailing
					return
				}
				fallthrough

			default:
				sendRobust = ircmsg.Bytes()
			}

		case err := <-ircSession.Errors:
			quitmsg = fmt.Sprintf("Bridge: Read from IRC client: %v", err)
			return

		case <-keepaliveToClient:
			// After no traffic in either direction for 1 minute, we send a PING
			// message. If a PING message was already sent, this means that we did
			// not receive a PONG message, so we close the connection with a
			// timeout.
			if waitingForPingReply {
				quitmsg = "Bridge: ping timeout"
				return
			}
			sendIRC = (&irc.Message{
				Command: irc.PING,
				Params:  []string{"robustirc.bridge"},
			}).Bytes()
			waitingForPingReply = true

		case <-keepaliveToNetwork:
			sendRobust = []byte("PING keepalive")
		}
	}
}

// Copied from src/net/http/server.go
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	return tc, nil
}

// maybeTLSListener returns a net.Listener which possibly uses TLS, depending
// on the -tls_cert_path and -tls_key_path flag values.
func maybeTLSListener(addr string) net.Listener {
	if *tlsCertPath == "" || *tlsKeyPath == "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		return ln
	}

	tlsconfig, err := makeTlsConfig()
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	return tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, tlsconfig)
}

func main() {
	flag.Parse()

	if os.Getenv("GOKRAZY_FIRST_START") == "1" {
		os.Exit(125) // on gokrazy.org, this program must be run via a wrapper
	}

	if *version {
		fmt.Println(robustsession.Version)
		return
	}

	rand.Seed(time.Now().Unix())

	if (*network == "" && *socks == "") ||
		(*socks == "" && *listen == "") {
		log.Fatal("You must specify either -network and -listen, or -socks.")
	}

	if *httpAddress != "" {
		go func() {
			log.Printf("-http listener failed: %v\n", http.ListenAndServe(*httpAddress, nil))
		}()
	}

	var listeners []net.Listener

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	go func() {
		sig := <-signalChan
		closeTimeout := 1 * time.Second
		log.Printf("Received signal %q, giving connections %v to close\n", sig, closeTimeout)
		for _, ln := range listeners {
			ln.Close()
		}
		time.Sleep(closeTimeout)
		log.Printf("Exiting due to signal %q\n", sig)
		os.Exit(int(syscall.SIGTERM) | 0x80)
	}()

	// SOCKS and IRC
	if *socks != "" && *network != "" && *listen != "" {
		ln := maybeTLSListener(*socks)
		listeners = append(listeners, ln)
		go func() {
			log.Printf("RobustIRC IRC bridge listening on %q (SOCKS). Specify an empty -socks= to disable.\n", *socks)
			if err := serveSocks(ln); err != nil {
				log.Fatal(err)
			}
		}()
	}

	// SOCKS only
	if *socks != "" && (*network == "" || *listen == "") {
		log.Printf("RobustIRC IRC bridge listening on %q (SOCKS). Specify an empty -socks= to disable.\n", *socks)
		log.Printf("Not listening on %q (IRC) because -network= was not specified.\n", *listen)
		ln := maybeTLSListener(*socks)
		listeners = append(listeners, ln)
		log.Fatal(serveSocks(ln))
	}

	// IRC
	if *network != "" && *listen != "" {
		p := newBridge(*network)

		for _, addr := range strings.Split(*listen, ",") {
			ln := maybeTLSListener(addr)
			listeners = append(listeners, ln)

			log.Printf("RobustIRC IRC bridge listening on %q (IRC)\n", addr)

			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Printf("Could not accept IRC client connection: %v\n", err)
						// Avoid flooding the logs with failed Accept()s.
						time.Sleep(1 * time.Second)
						continue
					}
					go p.handleIRC(conn)
				}
			}()
		}

		// Sleep forever
		<-make(chan struct{})
	}
}
