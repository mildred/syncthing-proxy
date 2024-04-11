package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/google/uuid"
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
	var val url.Values = url.Values{}
	val.Add("req", "checkauth")
	val.Add("user", user)
	val.Add("pass", pass)

	resp, err := a.client.PostForm(a.ServerUrl.String(), val)
	if err != nil {
		return false, fmt.Errorf("cannot request accountserver, %v", err)
	}

	defer resp.Body.Close()

	var result bool
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, fmt.Errorf("cannot decode accountserver response, %v", err)
	}

	return result, nil
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
	if h.clients == nil {
		h.clients = map[string]*http.Client{}
	}

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
		log.Printf("Error with accountserver for %s: %v", user, err)
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

	req.URL.Scheme = "http"
	req.URL.Host = req.Host

	req.Header.Del("Authenticate")

	delHopHeaders(req.Header)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error proxying request for %s (%v): %v", user, req.URL, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error proxying response for %s: %v", user, err)
	}
}

type ServeConfig struct {
	accountserver string
	handler *Handler
	server http.Server
}

func serve_dispatch(ctx context.Context, args []string) error {
	var server http.Server
	var accountServer string
	var err error
	handler := NewHandler()

	f := flag.NewFlagSet(os.Args[0] + " [dispatch]", flag.ExitOnError)
	f.StringVar(&accountServer, "a", "http://accountserver:8000", "Account Server")
	f.StringVar(&handler.TargetAddr, "t", "/run/syncthing/%{user}.socket", "Target unix socket to proxy")
	f.StringVar(&server.Addr, "l", ":8080", "Listen address and port or unix socket with \"unix:\" prefix (unless systemd socket activated)")
	f.Parse(args)

	handler.Accounts.ServerUrl, err = url.Parse(accountServer)
	if err != nil {
		return err
	}

	listeners, err := activation.Listeners()
	if err != nil {
		return err
	}

	if len(listeners) == 0 && (strings.HasPrefix(server.Addr, "unix:") || strings.HasPrefix(server.Addr, "unix/")) {
		var l net.Listener
		socket := server.Addr[5:]
		l, err = net.Listen("unix", socket)
		if err != nil {
			return fmt.Errorf("cannot listen to unix socket %+v: %v", socket, err)
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

func SleepContext(ctx context.Context, d time.Duration) error {
	sleep, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	<-sleep.Done()
	return ctx.Err()
}

type LockData struct {
	filename string
	UUID string
	Addresses []string
}

func (lock *LockData) Generate() error {
	lock.UUID = uuid.NewString()
	//. TODO: open public port and store the public address and socket in the lock
	return nil
}

func (lock *LockData) Read() error {
	f, err := os.Open(lock.filename)
	if err != nil {
		return err
	}

	defer f.Close()

	err = json.NewDecoder(f).Decode(lock)
	if err != nil {
		return err
	}

	return nil
}

func OpenLock(lock_file string) (*LockData, error) {
	lock := &LockData {
		filename: lock_file,
	}
	err := lock.Read()
	return lock, err
}

func TakeLock(ctx context.Context, config_dir string, cb func(context.Context, *LockData) error, wait func(context.Context, *LockData)) error {
	lock_file := path.Join(config_dir, "syncthing-proxy.lock")

	retry_interval := 30 * time.Second
	stale_interval := 2 * retry_interval
	renew_interval := 15 * time.Second

	var f *os.File = nil
	var lock LockData
	var owned atomic.Bool

	owned.Store(false)

	// When command stops, remove lock file
	defer func(){
		if owned.Load() {
			err := os.Remove(lock_file)
			if err == nil {
				log.Printf("Removed lock file: %s\n", lock_file)
			} else {
				log.Printf("Could not remove lock file %s: %e\n", lock_file, err)
			}
		} else {
			log.Printf("Lock file no longer owned by us: %s\n", lock_file)
		}
	}()

	wait_started := false
	waitCtx, cancelWait := context.WithCancel(ctx)
	defer cancelWait()

	// Loop until lock file acquired
	for f == nil {
		// Remove stale lock

		st, err := os.Stat(lock_file)
		if err == nil {
			if time.Since(st.ModTime()) > stale_interval {
				// WARNING : there is a race condition just here
				os.Remove(lock_file)
				log.Printf("Removed stale lock file %s\n", lock_file)
			}
		}

		// Try acquiring lock file
		f, err = os.OpenFile(lock_file, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
		
		if err != nil {
			if ! wait_started {
				log.Printf("Wait for lock file ready: %s\n", lock_file)
				lock2, err := OpenLock(lock_file)
				if err != nil {
					return fmt.Errorf("could not open lock, %e", err)
				}
				go wait(waitCtx, lock2)
				wait_started = true
			}
			SleepContext(ctx, retry_interval)
		}
	}

	// Lock file acquired: write UUID then close
	err := func() error {
		defer f.Close()
		owned.Store(true)

		log.Printf("Lock file acquired: %s\n", lock_file)

		err := lock.Generate()
		if err != nil {
			return fmt.Errorf("could not generate lock, %e", err)
		}

		err = json.NewEncoder(f).Encode(&lock)
		if err != nil {
			return fmt.Errorf("could not write JSON for lock, %e", err)
		}
		return nil
	}()
	if err != nil {
		return err
	}

	cancelWait()

	ctx1, cancel := context.WithCancel(ctx)
	defer cancel() // Will stop lock renewal too

	// Loop to ensure lock is held continuously
	go func(){
		for ctx1.Err() == nil {
			if SleepContext(ctx1, renew_interval) != nil {
				break
			}

			f, err := os.Open(lock_file)
			if err != nil {
				log.Printf("Cannot read lock file %s: %e\n", lock_file, err)
				cancel()
				break
			}

			func() {
				defer f.Close()

				var lock2 LockData
				err := json.NewDecoder(f).Decode(&lock2)
				if err != nil {
					owned.Store(false)
					log.Printf("Cannot decode lock file %s: %e\n", lock_file, err)
					cancel()
					return
				}

				if lock2.UUID != lock.UUID {
					owned.Store(false)
					log.Printf("Lock file %s UUID mismatch: expected %s, got %s\n", lock.UUID, lock2.UUID)
					cancel()
					return
				}

				now := time.Now()
				err = os.Chtimes(lock_file, now, now)
				if err != nil {
					log.Printf("Cannot renew lock file %s: %e\n", lock_file, err)
					cancel()
					return
				}
			}()
		}
	}()

	// Run command while lock is held
	return cb(ctx1, &lock)
}

func syncthing_serve(ctx context.Context, args []string) error {
	f := flag.NewFlagSet(os.Args[0] + " syncthing-serve", flag.ExitOnError)
	syncthing  := f.String("syncthing", "syncthing", "Syncthing executable")
	config_dir := f.String("config", "", "Config directory")
	data_dir   := f.String("data", "", "Data directory")
	socket     := f.String("socket", "", "Socket for GUI Address (--gui-address=unix:///path/to/socket)")
	f.Parse(args)

	cmd_args := []string{
		"serve",
		"--config=" + *config_dir,
		"--data=" + *data_dir,
		"--gui-address=unix://" + *socket,
	}

	for ctx.Err() == nil {
		err := TakeLock(ctx, *config_dir, func(ctx1 context.Context, lock *LockData) error {
			// TODO: open public facing proxy with encrypted transport for reverse
			// proxy, stop it when ctx1 is cancelled

			args := append(cmd_args, f.Args()...)
			log.Printf("Start %s %v", *syncthing, args)
			cmd := exec.CommandContext(ctx1, *syncthing, args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			err := cmd.Run()
			if err != nil {
				return fmt.Errorf("error from syncthing server, %e", err)
			}
			return nil
		}, func(ctx1 context.Context, lock *LockData) {
			// TODO: open up unix socket and set up forward proxy to live instance
			// close this proxy when ctx1 is cancelled
			// Use LockData as destination address
			// When reverse proxy fails, retry reading the LockData
			// from file to get new addresses
		})
		if err != nil {
			return fmt.Errorf("could not run syncthing iwithin lock, %e", err)
		}
	}
	return nil
}

func parse_args(ctx context.Context) error {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s [OPTIONS] [COMMAND] [ARGS...]:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Subcommands:\n")
		fmt.Fprintf(os.Stderr, "  dispatch (default)\n")
		fmt.Fprintf(os.Stderr, "        Authenticate and proxy Syncthing GUI using an accountserver\n")
		fmt.Fprintf(os.Stderr, "  syncthing-serve\n")
		fmt.Fprintf(os.Stderr, "        Handle starting syncthing server\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Global Flags:\n")
		flag.PrintDefaults()
	}

	versionFlag := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build: %s at %s\n", commit, date)
		return nil
	}

	args := flag.Args()
	var cmd string
	if len(args) >= 1 {
		cmd = args[0]
	}

	switch cmd {
	case "syncthing-serve":
		return syncthing_serve(ctx, args[1:])
	case "dispatch":
		return serve_dispatch(ctx, args[1:])
	default:
		return serve_dispatch(ctx, args)
	}
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

	if err := parse_args(ctx); err != nil {
		l.Printf("error: +%v\n", err)
	}
}
