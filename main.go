package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
)

// export GOFLAGS="-ldflags=-X=main.version=$(git describe --always HEAD)"
// https://goreleaser.com/cookbooks/using-main.version?h=version
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var l = log.Default()

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

type AccountServer struct {
	ServerUrl *url.URL
	client    http.Client
}

func (a AccountServer) RequestAuth(user, pass string) (bool, error) {
	var val url.Values
	val.Add("req", "checkauth")
	val.Add("user", user)
	val.Add("pass", pass)

	u, err := a.ServerUrl.Parse("?" + val.Encode())
	if err != nil {
		return false, err
	}

	resp, err := a.client.Get(u.String())
	if err != nil {
		return false, err
	}

	var result bool
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}

type Handler struct {
	Accounts   AccountServer
	TargetAddr string
	clients    map[string]*http.Client
}

func NewHandler() *Handler {
	return &Handler{
		clients: map[string]*http.Client{},
	}
}

func (h *Handler) getClient(target string) *http.Client {
	client := h.clients[target]

	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					dialer := net.Dialer{}
					return dialer.DialContext(ctx, "unix", target)
				},
			},
		}
		h.clients[target] = client
	}

	return client
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	user, pass, ok := req.BasicAuth()

	if ok {
		ok, err = h.Accounts.RequestAuth(user, pass)
	}
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !ok {
		// Request authentication
		w.Header().Set("WWW-Authenticate", `Basic realm="`+req.Host+`"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Reverse proxy
	target := strings.ReplaceAll(h.TargetAddr, "%{user}", user)
	client := h.getClient(target)

	//http: Request.RequestURI can't be set in client requests.
	//http://golang.org/src/pkg/net/http/client.go
	req.RequestURI = ""

	req.Header.Del("Authenticate")

	delHopHeaders(req.Header)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func serve(ctx context.Context) error {
	var server http.Server
	var accountServer string
	var err error
	handler := NewHandler()

	flag.StringVar(&accountServer, "a", "http://accountserver:8000", "Account Server")
	flag.StringVar(&handler.TargetAddr, "t", "/run/syncthing/%{user}.socket", "Target unix socket to proxy")
	flag.StringVar(&server.Addr, "l", ":8080", "Listen address and port or unix socket with \"unix:\" prefix (unless systemd socket activated)")
	versionFlag := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build: %s at %s\n", commit, date)
		return nil
	}

	handler.Accounts.ServerUrl, err = url.Parse(accountServer)
	if err != nil {
		return err
	}

	listeners, err := activation.Listeners()
	if err != nil {
		return err
	}

	if len(listeners) == 0 && strings.HasPrefix(server.Addr, "unix:") {
		var l net.Listener
		socket := server.Addr[5:]
		l, err = net.Listen("unix", socket)
		if err != nil {
			return fmt.Errorf("cannot listen to unix socket %+v: %e", socket, err)
		}

		listeners = append(listeners, l)
	}

	server.Handler = handler
	server.BaseContext = func(net.Listener) context.Context { return ctx }

	go func() {
		var err error
		if len(listeners) >= 1 {
			err = server.Serve(listeners[0])
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			l.Printf("listen: %+s\n", err)
			os.Exit(1)
		}
	}()

	l.Printf("Starting server on %v", server.Addr)
	<-ctx.Done()
	l.Printf("Stopping server")

	// Stoping server

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	err = server.Shutdown(ctxShutDown)
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	l.Printf("Server stopped")
	return nil
}

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		oscall := <-c
		l.Printf("system call: %+v", oscall)
		signal.Stop(c)
		cancel()
	}()

	if err := serve(ctx); err != nil {
		l.Printf("failed to serve: +%v\n", err)
	}
}
