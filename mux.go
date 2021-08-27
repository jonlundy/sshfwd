package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/soheilhy/cmux"
	"go.uber.org/multierr"
)

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
