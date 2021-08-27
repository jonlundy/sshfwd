package main

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
)

const (
	domainName = "prox.int"
	portRange  = "7000-7999"
	bindHost   = "[::1]"
)

var filterName = regexp.MustCompile("[^a-z0-9-]+")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	run(ctx)
}

func run(ctx context.Context) {
	lis, err := net.Listen("tcp", envMust("SSH_LISTEN"))
	if err != nil {
		log.Fatal(err.Error())
	}

	var opts []ssh.Option
	opts = append(
		opts,
		ssh.NoPty(),
	)

	hostKeys := envMust("SSH_HOSTKEYS")
	files, err := ioutil.ReadDir(hostKeys)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		opts = append(opts, ssh.HostKeyFile(filepath.Join(hostKeys, f.Name())))
	}

	srv := &server{
		bindHost:     envDefault("SSH_HOST", bindHost),
		domainName:   envDefault("SSH_DOMAIN", domainName),
		domainSuffix: envDefault("SSH_DOMAIN_SUFFIX", "."+domainName),
	}
	opts = append(opts, srv.optAuthUser()...)

	http.HandleFunc("/", srv.handleHTTP)
	mux := New(lis, srv.serveHTTP(ctx), srv.serveSSH(ctx, opts...))

	listen := mux.Listener.Addr().String()
	if idx := strings.LastIndex(listen, ":"); idx >= 0 {
		if i, err := strconv.Atoi(listen[idx+1:]); err == nil {
			srv.listenPort = uint32(i)
		}
	}

	if r := envDefault("SSH_PORTRANGE", portRange); r != "" {
		sp := strings.SplitN(r, "-", 2)
		if len(sp) == 1 {
			log.Fatal("SSH_PORTRANGE should have start and end like 7000-7999")
		}

		var p uint64
		if p, err = strconv.ParseUint(sp[0], 10, 32); err != nil {
			log.Fatal("SSH_PORTRANGE start port invalid:", sp[0])
		}
		srv.portStart = uint32(p)

		if p, err = strconv.ParseUint(sp[1], 10, 32); err != nil {
			log.Fatal("SSH_PORTRANGE end port invalid:", sp[1])
		}
		srv.portEnd = uint32(p)

		if srv.portStart > srv.portEnd {
			log.Fatalf("SSH_PORTRANGE is reversed %d > %d", srv.portStart, srv.portEnd)
		}
	}

	if err = mux.Serve(ctx); err != nil {
		log.Fatal()
	}
}

func envMust(s string) string {
	v := os.Getenv(s)
	if v == "" {
		log.Fatal("missing env ", s)
	}
	log.Println("env", s, "==", v)
	return v
}
func envDefault(s, d string) string {
	v := os.Getenv(s)
	if v == "" {
		v = d
	}
	log.Println("env", s, "==", v)
	return v
}
