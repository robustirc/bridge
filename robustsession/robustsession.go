// robustsession represents a RobustIRC session and handles all communication
// to the RobustIRC network.
package robustsession

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gopkg.in/sorcix/irc.v2"
)

const (
	pathCreateSession = "/robustirc/v1/session"
	pathDeleteSession = "/robustirc/v1/%s"
	pathPostMessage   = "/robustirc/v1/%s/message"
	pathGetMessages   = "/robustirc/v1/%s/messages?lastseen=%s"
)

const Version = "RobustIRC Bridge v1.8"

type robustId struct {
	Id    int64
	Reply int64
}

func (i *robustId) String() string {
	return fmt.Sprintf("%d.%d", i.Id, i.Reply)
}

type robustType int64

const (
	robustCreateSession = iota
	robustDeleteSession
	robustIRCFromClient
	robustIRCToClient
	robustPing
)

type robustMessage struct {
	Id      robustId
	Session robustId
	Type    robustType
	Data    string

	// List of all servers currently in the network. Only present when Type == RobustPing.
	Servers []string `json:",omitempty"`

	// ClientMessageId sent by client. Only present when Type == RobustIRCFromClient
	ClientMessageId uint64 `json:",omitempty"`
}

var (
	NoSuchSession = errors.New("No such RobustIRC session (killed by the network?)")

	networks   = make(map[string]*network)
	networksMu sync.Mutex
)

type backoffState struct {
	exp  float64
	next time.Time
}

type network struct {
	servers []string
	mu      sync.RWMutex
	backoff map[string]backoffState
}

func newNetwork(networkname string) (*network, error) {
	var servers []string

	parts := strings.Split(networkname, ",")
	if len(parts) > 1 {
		log.Printf("Interpreting %q as list of servers instead of network name\n", networkname)
		servers = parts
	} else {
		// Try to resolve the DNS name up to 5 times. This is to be nice to
		// people in environments with flaky network connections at boot, who,
		// for some reason, don’t run this program under systemd with
		// Restart=on-failure.
		try := 0
		for {
			_, addrs, err := net.LookupSRV("robustirc", "tcp", networkname)
			if err != nil {
				log.Println(err)
				if try < 4 {
					time.Sleep(time.Duration(int64(math.Pow(2, float64(try)))) * time.Second)
				} else {
					return nil, fmt.Errorf("DNS lookup of %q failed 5 times", networkname)
				}
				try++
				continue
			}
			// Randomly shuffle the addresses.
			for i := range addrs {
				j := rand.Intn(i + 1)
				addrs[i], addrs[j] = addrs[j], addrs[i]
			}
			for _, addr := range addrs {
				target := addr.Target
				if target[len(target)-1] == '.' {
					target = target[:len(target)-1]
				}
				servers = append(servers, fmt.Sprintf("%s:%d", target, addr.Port))
			}
			break
		}
	}

	return &network{
		servers: servers,
		backoff: make(map[string]backoffState),
	}, nil
}

// server (eventually) returns the host:port to which we should connect to. In
// case back-off prevents us from connecting anywhere right now, the function
// blocks until back-off is over.
func (n *network) server(random bool) string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	for {
		soonest := time.Duration(math.MaxInt64)
		// Try to use a random server, but fall back to using the next
		// available server in case the randomly picked server is unhealthy.
		if random {
			server := n.servers[rand.Intn(len(n.servers))]
			wait := n.backoff[server].next.Sub(time.Now())
			if wait <= 0 {
				return server
			}
		}
		for _, server := range n.servers {
			wait := n.backoff[server].next.Sub(time.Now())
			if wait <= 0 {
				return server
			}
			if wait < soonest {
				soonest = wait
			}
		}

		time.Sleep(soonest)
	}

	// Unreached, but necessary for compiling with go1.0.2 (debian stable).
	return ""
}

func (n *network) setServers(servers []string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// TODO(secure): we should clean up n.backoff from servers which no longer exist
	n.servers = servers
}

// prefer adds the specified server to the front of the servers list, thereby
// trying to prefer it over other servers for the next request. Note that
// exponential backoff overrides this, so this is only a hint, not a guarantee.
func (n *network) prefer(server string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.servers = append([]string{server}, n.servers...)
}

func (n *network) failed(server string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	b := n.backoff[server]
	// Cap the exponential backoff at 2^6 = 64 seconds. In that region, we run
	// into danger of the client disconnecting due to ping timeout.
	if b.exp < 6 {
		b.exp++
	}
	b.next = time.Now().Add(time.Duration(math.Pow(2, b.exp)) * time.Second)
	n.backoff[server] = b
}

func (n *network) succeeded(server string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.backoff, server)
}

func discardResponse(resp *http.Response) {
	// We need to read the entire body, otherwise net/http will not
	// re-use this connection.
	ioutil.ReadAll(resp.Body)
	resp.Body.Close()
}

type RobustSession struct {
	IrcPrefix *irc.Prefix
	Messages  chan string
	Errors    chan error

	sessionId string

	// ForwardedFor will be sent in all HTTP requests as X-Forwarded-For header
	// if non-empty.
	ForwardedFor string

	// BridgeAuth will be sent in all HTTP requests as X-Bridge-Auth header if
	// non-empty. See https://github.com/robustirc/robustirc/issues/122
	BridgeAuth string

	sessionAuth string
	deleted     bool
	done        chan bool
	network     *network
	client      *http.Client
	sendingMu   *sync.Mutex
}

func (s *RobustSession) sendRequest(method, path string, data []byte) (string, *http.Response, error) {
	for !s.deleted {
		// GET requests are for read-only state and can be answered by any server.
		target := s.network.server(method == "GET")
		requrl := fmt.Sprintf("https://%s%s", target, path)
		req, err := http.NewRequest(method, requrl, bytes.NewBuffer(data))
		if err != nil {
			return "", nil, err
		}
		req.Header.Set("User-Agent", Version)
		req.Header.Set("X-Session-Auth", s.sessionAuth)
		if s.ForwardedFor != "" {
			req.Header.Set("X-Forwarded-For", s.ForwardedFor)
		}
		if s.BridgeAuth != "" {
			req.Header.Set("X-Bridge-Auth", s.BridgeAuth)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			s.network.failed(target)
			log.Printf("Warning: %s: %v (trying different server)\n", requrl, err)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			if cl := resp.Header.Get("Content-Location"); cl != "" {
				if location, err := url.Parse(cl); err == nil {
					s.network.prefer(location.Host)
				}
			}

			return target, resp, nil
		}
		message, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		s.network.failed(target)
		if resp.StatusCode == http.StatusNotFound {
			return "", nil, fmt.Errorf("Error: %s: %v (non-recoverable)\n", requrl, NoSuchSession)
		}
		// Server errors, temporary.
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			log.Printf("Warning: %s: %v: %q (trying different server)\n", requrl, resp.Status, message)
			continue
		}
		// Client errors and anything unexpected, assumed to be permanent.
		return "", nil, fmt.Errorf("Error: %s: %v: %q (non-recoverable)\n", requrl, resp.Status, message)
	}

	return "", nil, NoSuchSession
}

// Create creates a new RobustIRC session. It resolves the given network name
// (e.g. "robustirc.net") to a set of servers by querying the
// _robustirc._tcp.<network> SRV record and sends the CreateSession request.
//
// When err == nil, the caller MUST read the RobustSession.Messages and
// RobustSession.Errors channels.
//
// tlsCAFile specifies the path to an x509 root certificate, which is mostly
// useful for testing. If empty, the system CA store will be used
// (recommended).
func Create(network string, tlsCAFile string) (*RobustSession, error) {
	networksMu.Lock()
	n, ok := networks[network]
	if !ok {
		var err error
		n, err = newNetwork(network)
		if err != nil {
			networksMu.Unlock()
			return nil, err
		}
		networks[network] = n
	}
	networksMu.Unlock()

	var tlsConfig *tls.Config

	if tlsCAFile != "" {
		roots := x509.NewCertPool()
		contents, err := ioutil.ReadFile(tlsCAFile)
		if err != nil {
			log.Fatalf("Could not read cert.pem: %v", err)
		}
		if !roots.AppendCertsFromPEM(contents) {
			log.Fatalf("Could not parse %q", tlsCAFile)
		}
		tlsConfig = &tls.Config{RootCAs: roots}
	}

	// This is copied from net/http.DefaultTransport as of go1.4.
	transport := &http.Transport{
		// The 70s timeout has been chosen such that:
		// 1) It is higher than the interval with which the server sends pings
		//    to us (20s).
		// 2) It is higher than the interval with which we send pings to the
		//    server (60s) so that the connections can be re-used (HTTP
		//    keepalive).
		Dial:                DeadlineConnDialer(5*time.Second, 30*time.Second, 70*time.Second),
		TLSClientConfig:     tlsConfig,
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 1,
	}

	setupTLSHandshakeTimeout(transport, 10*time.Second)

	client := &http.Client{Transport: transport}

	s := &RobustSession{
		Messages:  make(chan string),
		Errors:    make(chan error),
		done:      make(chan bool),
		network:   n,
		client:    client,
		sendingMu: &sync.Mutex{},
	}

	_, resp, err := s.sendRequest("POST", pathCreateSession, nil)
	if err != nil {
		return nil, err
	}
	defer discardResponse(resp)

	var createSessionReply struct {
		Sessionid   string
		Sessionauth string
		Prefix      string
	}

	if err := json.NewDecoder(resp.Body).Decode(&createSessionReply); err != nil {
		return nil, err
	}

	s.sessionId = createSessionReply.Sessionid
	s.sessionAuth = createSessionReply.Sessionauth
	s.IrcPrefix = &irc.Prefix{Name: createSessionReply.Prefix}

	go s.getMessages()

	return s, nil
}

func (s *RobustSession) getMessages() {
	var lastseen robustId

	defer func() {
		for _ = range s.done {
		}
	}()

	for !s.deleted {
		target, resp, err := s.sendRequest("GET", fmt.Sprintf(pathGetMessages, s.sessionId, lastseen.String()), nil)
		if err != nil {
			s.Errors <- err
			return
		}

		dec := json.NewDecoder(resp.Body)
		for !s.deleted {
			var msg robustMessage
			if err := dec.Decode(&msg); err != nil {
				if !s.deleted {
					log.Printf("Protocol error on %q: Could not decode response chunk as JSON: %v\n", target, err)
				}
				s.network.failed(target)
				break
			}
			if msg.Type == robustPing {
				if len(msg.Servers) > 0 {
					s.network.setServers(msg.Servers)
				}
			} else if msg.Type == robustIRCToClient {
				s.Messages <- msg.Data
				lastseen = msg.Id
			}
		}

		// Cannot use discardResponse() because the response never completes.
		resp.Body.Close()

		// Delay reconnecting for somewhere in between [250, 500) ms to avoid
		// overloading the remaining servers from many clients at once when one
		// server fails.
		time.Sleep(time.Duration(250+rand.Int63n(250)) * time.Millisecond)
	}
}

// SessionId returns a string that identifies the session. It should be used in
// log messages to identify sessions.
func (s *RobustSession) SessionId() string {
	return s.sessionId
}

// PostMessage posts the given IRC message. It will retry automatically on
// transient errors, and only return an error when the network returned a
// permanent error, such as NoSuchSession.
//
// The RobustIRC protocol dictates that you must not try to send more than one
// message at any given point in time, and PostMessage enforces this by using a
// mutex.
func (s *RobustSession) PostMessage(message string) error {
	s.sendingMu.Lock()
	defer s.sendingMu.Unlock()
	type postMessageRequest struct {
		Data            string
		ClientMessageId uint64
	}

	h := fnv.New32()
	h.Write([]byte(message))
	// The message id should be unique across separate instances of the bridge,
	// even if they were attached to the same session. A collision in this case
	// means one bridge instance (with the same session) is unable to send a
	// message because the message id is equal to the one the other bridge
	// instance just sent. With the hash of the message itself, such a
	// collision can only occur when both instances try to send exactly the
	// same message _and_ the random value is the same for both instances.
	msgid := (uint64(h.Sum32()) << 32) | uint64(rand.Int31n(math.MaxInt32))

	b, err := json.Marshal(postMessageRequest{
		Data:            message,
		ClientMessageId: msgid,
	})
	if err != nil {
		return fmt.Errorf("Message could not be encoded as JSON: %v\n", err)
	}

	target, resp, err := s.sendRequest("POST", fmt.Sprintf(pathPostMessage, s.sessionId), b)
	if err != nil {
		return err
	}
	discardResponse(resp)
	s.network.succeeded(target)
	return nil
}

// Delete sends a delete request for this session on the server.
//
// This session MUST not be used after this method returns. Even if the delete
// request did not succeed, the session is deleted from the client’s point of
// view.
func (s *RobustSession) Delete(quitmessage string) error {
	defer func() {
		s.deleted = true

		// Make sure nobody is blocked on sending to the channel by closing them
		// and reading all remaining values.
		go func() {
			for _ = range s.Messages {
			}
		}()
		go func() {
			for _ = range s.Errors {
			}
		}()

		// This will be read by getMessages(), which will not send on the
		// channels after reading it, so we can safely close them.
		s.done <- true
		close(s.done)

		close(s.Messages)
		close(s.Errors)

		if transport, ok := s.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}()

	b, err := json.Marshal(struct{ Quitmessage string }{quitmessage})
	if err != nil {
		return err
	}
	_, resp, err := s.sendRequest("DELETE", fmt.Sprintf(pathDeleteSession, s.sessionId), b)
	if err != nil {
		return err
	}
	discardResponse(resp)
	return nil
}
