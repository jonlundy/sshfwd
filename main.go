package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/gliderlabs/ssh"
)

func main() {
	run()
}

func run() {
	var opts []ssh.Option
	opts = append(
		opts,
		ssh.NoPty(),
		optRemoteAllow(),
	)

	files, err := ioutil.ReadDir(envMust("SSH_HOSTKEYS"))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		opts = append(opts, ssh.HostKeyFile(filepath.Join(envMust("SSH_HOSTKEYS"), f.Name())))
	}

	if authKeys := os.Getenv("SSH_AUTHKEYS"); authKeys != "" {
		opts = append(opts, optPubkeyAllow(authKeys))
	}

	log.Fatal(ssh.ListenAndServe(
		envMust("SSH_LISTEN"),
		newSession(context.Background()),
		opts...,
	))
}

func envMust(s string) string {
	v := os.Getenv(s)
	if v == "" {
		log.Fatal("missing env ", s)
	}
	return v
}

func newSession(ctx context.Context) func(ssh.Session) {
	return func(s ssh.Session) {
		if _, err := fmt.Fprintf(s, "Hello %s\n", s.User()); err != nil {
			return
		}

		<-ctx.Done()
	}
}

func optRemoteAllow() ssh.Option {
	return func(cfg *ssh.Server) error {
		hdlr := ssh.ForwardedTCPHandler{}

		if cfg.RequestHandlers == nil {
			cfg.RequestHandlers = make(map[string]ssh.RequestHandler, 2)
		}

		cfg.RequestHandlers["tcpip-forward"] = hdlr.HandleSSHRequest
		cfg.RequestHandlers["cancel-tcpip-forward"] = hdlr.HandleSSHRequest

		cfg.ReversePortForwardingCallback = func(ctx ssh.Context, bindHost string, bindPort uint32) bool {
			log.Println("Allow Remote:", bindHost, bindPort)

			return true
		}

		return nil
	}
}

func optPubkeyAllow(path string) ssh.Option {
	return ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {
			fname := filepath.Join(path, f.Name())
			data, _ := ioutil.ReadFile(fname)
			allowed, _, _, _, _ := ssh.ParseAuthorizedKey(data)
			if ssh.KeysEqual(key, allowed) {
				log.Println("Authorized:", fname)
				return true
			}
		}

		return false
	})
}
