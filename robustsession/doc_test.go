package robustsession_test

import (
	"log"

	"github.com/robustirc/bridge/robustsession"
)

func ExampleRobustSession() {
	session, err := robustsession.Create("robustirc.net", "")
	if err != nil {
		log.Fatalf("Could not create robustsession: %v", err)
	}
	go func() {
		for msg := range session.Messages {
			log.Printf("<- %s\n", msg)
		}
	}()
	go func() {
		for err := range session.Errors {
			log.Fatalf("RobustSession error: %v", err)
		}
	}()

	input := []string{
		"NICK example",
		"USER docs * 0 :Example User",
		"JOIN #robustirc",
		"PRIVMSG #robustirc :trying out the example :)",
		"QUIT :woohoo",
		"PRIVMSG #robustirc :this will trigger an error",
	}
	for _, msg := range input {
		log.Printf("-> %s\n", msg)
		if err := session.PostMessage(msg); err != nil {
			log.Fatal(err)
		}
	}
}
