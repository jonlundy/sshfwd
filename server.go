package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/wolfeidau/humanhash"
)

var (
	//go:embed pages/* layouts/* assets/*
	files     embed.FS
	templates map[string]*template.Template
)

type user struct {
	Name      string
	Pubkey    ssh.PublicKey
	BindHost  string
	BindPort  uint32
	ctx       ssh.Context
	proxy     http.Handler
	LastLogin time.Time
}

func (u *user) Active() bool { return u.ctx != nil }

func (u *user) String() string {
	var b strings.Builder
	fmt.Fprintln(&b, "User:     ", u.Name)
	fmt.Fprintf(&b, "  Ptr:     %p\n", u)
	fmt.Fprintf(&b, "  Pubkey:  %x\n", u.Pubkey)
	fmt.Fprintln(&b, "  Host:   ", u.BindHost)
	fmt.Fprintln(&b, "  Port:   ", u.BindPort)
	fmt.Fprintf(&b, "  Active:  %t\n", u.ctx != nil)
	fmt.Fprintln(&b, "  LastLog:", u.LastLogin)
	return b.String()
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

func (s *server) String() string {
	var b strings.Builder
	fmt.Fprintln(&b, "Server:     ", s.domainName)
	fmt.Fprintln(&b, "  Port:     ", s.listenPort)
	fmt.Fprintln(&b, "  Suffix:   ", s.domainSuffix)
	fmt.Fprintln(&b, "  BindHost: ", s.bindHost)
	fmt.Fprintf(&b, "  PortRange: %d-%d\n", s.portStart, s.portEnd)
	fmt.Fprintln(&b, "  NextPort: ", s.portNext)
	return b.String()
}

// User Operations
func (srv *server) addUser(pubkey ssh.PublicKey) *user {
	u := &user{}

	u.LastLogin = time.Now()
	u.Name = fingerprintHuman(pubkey)
	u.Name = strings.ToLower(u.Name)
	u.Name = filterName.ReplaceAllString(u.Name, "")

	if g, ok := srv.users.LoadOrStore(u.Name, u); ok {
		u = g.(*user)
		return u
	}

	u.Pubkey = pubkey
	u.BindPort = srv.nextPort()
	u.BindHost = srv.bindHost

	return u
}
func (srv *server) disconnectUser(name string) {
	if u, ok := srv.getUserByName(name); ok {
		u.ctx = nil
		u.proxy = nil
		srv.ports.Delete(u.BindPort)
	}
}
func (srv *server) getUserByPort(port uint32) (*user, bool) {
	if u, ok := srv.ports.Load(port); ok {
		log.Printf("%d %T %s", port, u, u)

		if u, ok := u.(*user); ok {
			return u, true
		} else {
			log.Println("port not found", port, ok)
		}
	}
	return nil, false
}
func (srv *server) getUserByName(name string) (*user, bool) {
	if u, ok := srv.users.Load(name); ok {
		if u, ok := u.(*user); ok {
			return u, true
		} else {
			log.Println("user not found", name, ok)
		}
	}
	return nil, false
}
func (srv *server) listUsers() []*user {
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
func (srv *server) listPorts() map[uint32]*user {
	lis := make(map[uint32]*user)
	srv.ports.Range(func(key, value interface{}) bool {
		if u, ok := value.(*user); ok {
			lis[key.(uint32)] = u
			return true
		} else {
			fmt.Println(key, value)
		}
		return false
	})

	return lis
}

func (srv *server) nextPort() uint32 {
	if srv.portNext < srv.portStart || srv.portNext > srv.portEnd {
		srv.portNext = srv.portStart
	}

	defer func() { srv.portNext++ }()

	return srv.portNext
}

// SSH Operations
func (srv *server) serveSSH(ctx context.Context, opts ...ssh.Option) func(l net.Listener) error {
	return func(l net.Listener) error {
		return ssh.Serve(
			l,
			srv.newSession(ctx),
			opts...,
		)
	}
}
func (srv *server) newSession(ctx context.Context) func(ssh.Session) {
	return func(s ssh.Session) {
		if _, err := fmt.Fprintf(s, "Hello %s\n", s.User()); err != nil {
			return
		}

		if u, ok := srv.getUserByName(s.User()); ok {
			host := fmt.Sprintf("%v:%v", "localhost", u.BindPort)
			director := func(req *http.Request) {
				if h := req.Header.Get("X-Forwarded-Host"); h == "" {
					req.Header.Set("X-Forwarded-Host", req.Host)
				}
				req.Header.Set("X-Origin-Host", host)
				req.URL.Scheme = "http"
				req.URL.Host = host

				requestDump, err := httputil.DumpRequest(req, req.Method == http.MethodPost || req.Method == http.MethodPut)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Fprintln(s, string(requestDump))
			}
			u.proxy = &httputil.ReverseProxy{Director: director}
			fmt.Fprintf(s, "Created HTTP listener at: %v%v\n\n", u.Name, srv.domainSuffix)
		}

		select {
		case <-ctx.Done():
			log.Println("server shutting down")
		case <-s.Context().Done():
			log.Println("user", s.User(), "disconnected")
		}

		srv.disconnectUser(s.User())
		if _, err := fmt.Fprintf(s, "Goodbye! %s\n", s.User()); err != nil {
			return
		}
	}
}
func (srv *server) optAuthUser() []ssh.Option {
	return []ssh.Option{
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			u, ok := srv.getUserByName(ctx.User())
			if !ok {
				log.Println("user not found", ctx.User())
				return false
			}

			if ssh.KeysEqual(key, u.Pubkey) {
				log.Println("User:", ctx.User(), "Authorized:", u.BindHost, u.BindPort, ctx.ClientVersion(), ctx.SessionID(), ctx.LocalAddr(), ctx.RemoteAddr())
				u.ctx = ctx
				u.LastLogin = time.Now()
				if _, loaded := srv.ports.LoadOrStore(u.BindPort, u); loaded {
					log.Println("User:", ctx.User(), "already connected!")
					return false
				}
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
				u, ok := srv.getUserByPort(bindPort)
				if !ok {
					log.Println("User port", bindPort, "not authorized.")
					return false
				}

				if u.ctx.SessionID() != ctx.SessionID() {
					log.Println("Port", bindPort, "in use by", u.Name, u.ctx.SessionID())
					return false
				}

				if bindHost != "localhost" || bindPort != u.BindPort {
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

// HTTP Operations
func (srv *server) serveHTTP(ctx context.Context) func(net.Listener) error {
	s := &http.Server{
		ReadTimeout:  2500 * time.Millisecond,
		WriteTimeout: 5 * time.Second,
		Handler:      http.DefaultServeMux,
		BaseContext:  func(net.Listener) context.Context { return ctx },
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
		u, ok := srv.getUserByName(name)
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
			fmt.Fprintln(rw, "ERR READING KEY", err)
			return
		}
		u := srv.addUser(pubkey)
		rw.Header().Set("Location", "/")
		rw.WriteHeader(http.StatusFound)
		fmt.Fprintf(rw, `ssh -T -p %v %v@%v -R "%v:%v:localhost:$LOCAL_PORT" -i $PRIV_KEY`+"\n", srv.listenPort, u.Name, srv.domainName, u.BindHost, u.BindPort)
		return
	}

	// fmt.Fprintln(rw, "Hello!")
	// fmt.Fprintln(rw, srv)
	// fmt.Fprintln(rw, "Registered Users")
	// for _, u := range srv.listUsers() {
	// 	fmt.Fprintln(rw, u)
	// }

	// fmt.Fprintln(rw, "Connected Users")
	// for _, u := range srv.listConnectedUsers() {
	// 	fmt.Fprintln(rw, u)
	// }

	a, _ := fs.Sub(files, "assets")
	assets := http.StripPrefix("/assets/", http.FileServer(http.FS(a)))
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		assets.ServeHTTP(rw, r)
		return
	}

	t := templates["home.go.tpl"]
	err := t.Execute(rw, map[string]any{
		"Users":      srv.listUsers(),
		"Ports":      srv.listPorts(),
		"ListenPort": srv.listenPort,
		"DomainName": srv.domainName,
	})
	if err != nil {
		log.Println(err)
	}
}

func fingerprintHuman(pubKey ssh.PublicKey) string {
	sha256sum := sha256.Sum256(pubKey.Marshal())
	h, _ := humanhash.Humanize(sha256sum[:], 3)
	return h
}

var funcMap = map[string]any{}

func loadTemplates() error {
	if templates != nil {
		return nil
	}
	templates = make(map[string]*template.Template)
	tmplFiles, err := fs.ReadDir(files, "pages")
	if err != nil {
		return err
	}

	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}
		pt := template.New(tmpl.Name())
		pt.Funcs(funcMap)
		pt, err = pt.ParseFS(files, "pages/"+tmpl.Name(), "layouts/*.go.tpl")
		if err != nil {
			log.Println(err)

			return err
		}
		templates[tmpl.Name()] = pt
	}
	return nil
}
