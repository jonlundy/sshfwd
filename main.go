package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/soheilhy/cmux"
	"github.com/tjarratt/babble"
	"go.uber.org/multierr"
)

const (
	domainName          = "prox.int"
	domainSuffix        = ".prox.int"
	portStart    uint32 = 4000
	portEnd      uint32 = 4999
	bindHost            = "[::1]"
)

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

	files, err := ioutil.ReadDir(envMust("SSH_HOSTKEYS"))
	if err != nil {
		log.Fatal(err)
	}

	srv := &server{
		bindHost:     envDefault("SSH_HOST", bindHost),
		portStart:    portStart,
		portEnd:      portEnd,
		domainName:   envDefault("SSH_DOMAIN", domainName),
		domainSuffix: envDefault("SSH_DOMAIN_SUFFIX", domainSuffix),
	}

	for _, f := range files {
		opts = append(opts, ssh.HostKeyFile(filepath.Join(envMust("SSH_HOSTKEYS"), f.Name())))
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

	log.Fatal(mux.Serve(ctx))
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
		return d
	}
	log.Println("env", s, "==", v)
	return v
}

func (srv *server) newSession(ctx context.Context) func(ssh.Session) {
	return func(s ssh.Session) {
		if _, err := fmt.Fprintf(s, "Hello %s\n", s.User()); err != nil {
			return
		}

		if u, ok := srv.GetUserByName(s.User()); ok {
			host := fmt.Sprintf("%v:%v", u.bindHost, u.bindPort)
			director := func(req *http.Request) {
				if h := req.Header.Get("X-Forwarded-Host"); h == "" {
					req.Header.Set("X-Forwarded-Host", req.Host)
				}
				req.Header.Set("X-Origin-Host", host)
				req.URL.Scheme = "http"
				req.URL.Host = host
			}
			u.proxy = &httputil.ReverseProxy{Director: director}
			fmt.Fprintf(s, "Created HTTP listener at: %v%v\n", u.name, srv.domainSuffix)
		}

		<-ctx.Done()

		if _, err := fmt.Fprintf(s, "Goodbye! %s\n", s.User()); err != nil {
			return
		}
	}
}

type server struct {
	listenPort   uint32
	domainName   string
	domainSuffix string
	bindHost     string

	portStart uint32
	portEnd   uint32
	portNext  uint32

	ports sync.Map
	users sync.Map
}

type user struct {
	name     string
	pubkey   ssh.PublicKey
	bindHost string
	bindPort uint32
	ctx      ssh.Context
	proxy    http.Handler
}

func (srv *server) AddUser(pubkey ssh.PublicKey) *user {
	u := &user{}
	u.pubkey = pubkey

	babbler := babble.NewBabbler()
	u.name = strings.ToLower(babbler.Babble())

	u.bindPort = srv.nextPort()
	u.bindHost = srv.bindHost

	srv.users.Store(u.name, u)

	return u
}
func (srv *server) nextPort() uint32 {
	if srv.portNext < srv.portStart || srv.portNext > srv.portEnd {
		srv.portNext = srv.portStart
	}

	defer func() { srv.portNext++ }()

	return srv.portNext
}

func (srv *server) GetUserByPort(port uint32) (*user, bool) {
	if u, ok := srv.ports.Load(port); ok {
		if u, ok := u.(*user); ok {
			return u, true
		}
	}
	return nil, false
}
func (srv *server) GetUserByName(name string) (*user, bool) {
	if u, ok := srv.users.Load(name); ok {
		if u, ok := u.(*user); ok {
			return u, true
		}
	}
	return nil, false
}
func (srv *server) ListUsers() []*user {
	var lis []*user
	srv.users.Range(func(key, value interface{}) bool {
		if u, ok := value.(*user); ok {
			lis = append(lis, u)
			return true
		} else {
			fmt.Println(key, value)

		}
		return false
	})

	return lis
}
func (srv *server) ListConnectedUsers() []*user {
	var lis []*user
	srv.ports.Range(func(key, value interface{}) bool {
		if u, ok := value.(*user); ok {
			lis = append(lis, u)
			return true
		}
		return false
	})

	return lis
}
func (srv *server) optAuthUser() []ssh.Option {
	return []ssh.Option{
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			u, ok := srv.GetUserByName(ctx.User())
			if !ok {
				log.Println("user not found", ctx.User())
				return false
			}

			if ssh.KeysEqual(key, u.pubkey) {
				log.Println("User: ", ctx.User(), "Authorized:", u.bindHost, u.bindPort, ctx.ClientVersion(), ctx.SessionID(), ctx.LocalAddr(), ctx.RemoteAddr())
				u.ctx = ctx
				srv.ports.Store(u.bindPort, u)
				return true
			}

			return false
		}),
		func(cfg *ssh.Server) error {
			hdlr := ssh.ForwardedTCPHandler{}

			if cfg.RequestHandlers == nil {
				cfg.RequestHandlers = make(map[string]ssh.RequestHandler, 2)
			}

			cfg.RequestHandlers["tcpip-forward"] = hdlr.HandleSSHRequest
			cfg.RequestHandlers["cancel-tcpip-forward"] = hdlr.HandleSSHRequest

			cfg.ReversePortForwardingCallback = func(ctx ssh.Context, bindHost string, bindPort uint32) bool {
				u, ok := srv.GetUserByPort(bindPort)
				if !ok {
					log.Println("User port", bindPort, "not authorized.")
					return false
				}

				if u.ctx.SessionID() != ctx.SessionID() {
					log.Println("Port", bindPort, "in use by", u.name, u.ctx.SessionID())
					return false
				}

				if bindHost != strings.Trim(u.bindHost, "[]") || bindPort != u.bindPort {
					log.Println("User", ctx.User(), "Not Allowed: ", bindHost, bindPort, ctx.ClientVersion(), ctx.SessionID(), ctx.LocalAddr(), ctx.RemoteAddr())
					return false
				}

				log.Println("User", ctx.User(), "Allow Remote:", bindHost, bindPort, ctx.ClientVersion(), ctx.SessionID(), ctx.LocalAddr(), ctx.RemoteAddr())
				return true
			}

			return nil
		},
	}
}

func (srv *server) serveSSH(ctx context.Context, opts ...ssh.Option) func(l net.Listener) error {
	return func(l net.Listener) error {
		return ssh.Serve(
			l,
			srv.newSession(ctx),
			opts...,
		)
	}
}
func (srv *server) serveHTTP(ctx context.Context) func(net.Listener) error {
	s := &http.Server{
		ReadTimeout:  2500 * time.Millisecond,
		WriteTimeout: 5 * time.Second,
		Handler:      http.DefaultServeMux,
	}

	go func(ctx context.Context) {
		<-ctx.Done()
		s.Shutdown(context.Background())
	}(ctx)

	return s.Serve
}

func (srv *server) handleHTTP(rw http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.Host, srv.domainSuffix) {
		name := strings.TrimSuffix(r.Host, srv.domainSuffix)
		u, ok := srv.GetUserByName(name)
		if !ok || u.proxy == nil {
			fmt.Fprintln(rw, "NOT FOUND", name)
		}
		u.proxy.ServeHTTP(rw, r)
		return
	}

	if r.Method == http.MethodPost {
		pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.FormValue("pub")))
		if err != nil {
			rw.WriteHeader(400)
			fmt.Fprintln(rw, "ERR READING KEY")
			return
		}
		u := srv.AddUser(pubkey)
		rw.WriteHeader(201)
		fmt.Fprintf(rw, `ssh -T -p %v %v@%v -R "%v:%v:localhost:$LOCAL_PORT" -i $PRIV_KEY`, srv.listenPort, u.name, srv.domainName, u.bindHost, u.bindPort)
		return
	}

	fmt.Fprintln(rw, "Hello!", r.Host, r.URL)
	for _, u := range srv.ListUsers() {
		fmt.Fprintln(rw, "User:", u.name)
	}
	for _, u := range srv.ListConnectedUsers() {
		fmt.Fprintln(rw, "Conn:", u.name)
	}
}

// serverMux is mux server which will multiplex a listener to serve an http
// server using the http.DefaultServeMux handler, as well as a grpc server
// to serve a protobuf generated grpc.serverMux
type serverMux struct {
	Listener net.Listener
	HTTP     func(net.Listener) error
	SSH      func(net.Listener) error
	ServeMux *http.ServeMux
}

func New(lis net.Listener, http, ssh func(net.Listener) error) *serverMux {
	return &serverMux{
		Listener: lis,
		HTTP:     http,
		SSH:      ssh,
	}
}

// Serve begins serving a multiplexed server. Any errors returned before the stop
// signal is given indicate a failure of the server to start or an unexpected shutdown.
// Serve closes the listener once Shutdown has been triggered
func (m *serverMux) Serve(ctx context.Context) error {
	errChanSSH := make(chan error)
	errChanHTTP := make(chan error)

	defer func() {
		err := multierr.Combine(m.Listener.Close(), <-errChanSSH, <-errChanHTTP)
		if err != nil {
			log.Println(err)
		}
	}()

	mux := cmux.New(m.Listener)
	httpL := mux.Match(cmux.HTTP1Fast())
	sshL := mux.Match(cmux.Any())

	go func() {
		defer close(errChanSSH)
		if err := m.SSH(sshL); err != nil {
			switch err {
			case cmux.ErrServerClosed:
				log.Println("shutting down SSH Server")
			default:
				errChanSSH <- fmt.Errorf("failed to start SSH: %w", err)
			}
		}
	}()

	go func() {
		defer close(errChanHTTP)
		if err := m.HTTP(httpL); err != nil {
			switch err {
			case cmux.ErrServerClosed:
				log.Println("shutting down HTTP Server")
			default:
				errChanHTTP <- fmt.Errorf("failed to start HTTP: %w", err)
			}
		}
	}()

	errChan := make(chan error)
	go func() {
		defer close(errChan)
		err := mux.Serve()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				log.Println("shutting down mux server")
			} else {
				errChan <- fmt.Errorf("failed to start server multiplexing: %w", err)
			}
		}
	}()

	log.Println("server started: multiplexed http/1, http/2",
		"address", m.Listener.Addr().String(),
		"multiplexed", "true",
	)

	defer mux.Close()

	select {
	case <-ctx.Done():
		log.Println("stopping multiplexed server gracefully")
		return nil
	case err := <-errChanSSH:
		return err
	case err := <-errChanHTTP:
		return err
	case err := <-errChan:
		return err
	}
}
