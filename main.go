package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"errors"
	"flag"
	"fmt"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/message/peer"
	"github.com/gotd/td/tg"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"
	"math/rand"
	"os"
	"strings"
)

type termAuth struct {
	phone string
}

func (a termAuth) AcceptTermsOfService(_ context.Context, tos tg.HelpTermsOfService) error {
	return &auth.SignUpRequired{TermsOfService: tos}
}

func (a termAuth) SignUp(_ context.Context) (auth.UserInfo, error) {
	return auth.UserInfo{}, errors.New("not implemented")
}

func (a termAuth) Phone(_ context.Context) (string, error) {
	return a.phone, nil
}

func (a termAuth) Password(_ context.Context) (string, error) {
	fmt.Print("Enter 2FA password: ")
	bytePwd, err := terminal.ReadPassword(0)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePwd)), nil
}

func (a termAuth) Code(_ context.Context, _ *tg.AuthSentCode) (string, error) {
	fmt.Print("Enter code: ")
	code, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(code), nil
}

func main() {

	if len(os.Args[1:]) < 2 {
		fmt.Println("Usage: ... -u {username} -phone {phone}")
		return
	}

	username := flag.String("u", "123", "username of target account telegram")
	phone := flag.String("phone", "123", "phone of your account telegram")

	flag.Parse()

	sessionsDirectory := "sessions"
	sessionPath := fmt.Sprintf("%s/%x.session",
		sessionsDirectory, md5.Sum([]byte(*phone)))

	if _, err := os.Stat(sessionsDirectory); os.IsNotExist(err) {
		if err := os.Mkdir(sessionsDirectory, os.ModeSticky|os.ModePerm); err != nil {
			panic(err)
		}
	}

	log, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer func() { _ = log.Sync() }()
	// No graceful shutdown.
	ctx := context.Background()

	// Setting up authentication flow helper based on terminal auth.
	flow := auth.NewFlow(
		termAuth{phone: *phone},
		auth.SendCodeOptions{},
	)

	client, _ := telegram.ClientFromEnvironment(telegram.Options{
		SessionStorage: &session.FileStorage{
			Path: sessionPath,
		},
		Logger: log,
	})

	if err := client.Run(ctx, func(ctx context.Context) error {
		if err := client.Auth().IfNecessary(ctx, flow); err != nil {
			return err
		}

		api := client.API()

		resolver := peer.DefaultResolver(api)
		userPeer, err := resolver.ResolveDomain(ctx, *username)

		if err != nil {
			panic(err)
		}

		_, err = api.MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
			Background: false,
			RandomID:   int64(rand.Uint64()),
			Message:    "Some the string",
			Peer:       userPeer,
		})

		if err != nil {
			return err
		}

		// Return to close client connection and free up resources.
		return nil
	}); err != nil {
		panic(err)
	}
}
