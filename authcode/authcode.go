package authcode

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net"
	"net/http"
	"net/url"
)

const openPath = "/login"

// AskBrowser gets an OAuth2 access code via the default web browser
// accessing a short-lived web server.
func AskBrowser(c *oauth2.Config) (string, error) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	u, err := url.Parse(c.RedirectURL)
	if err != nil {
		return "", err
	}
	addr := u.Host

	// XXX require :port

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// State is a CSRF stafeguard
	stateBytes := make([]byte, 16)
	_, err = rand.Read(stateBytes)
	if err != nil {
		return "", err
	}
	state := fmt.Sprintf("%x", stateBytes)

	mux.HandleFunc(openPath, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, c.AuthCodeURL(state), http.StatusTemporaryRedirect)
	})

	mux.HandleFunc(u.Path, func(w http.ResponseWriter, req *http.Request) {
		s := req.URL.Query().Get("state")
		if s != state {
			errChan <- errors.New("authentication state mismatch")
			return
		}

		w.Write([]byte("close me."))
		codeChan <- req.URL.Query().Get("code")
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}

	go func() {
		errChan <- server.Serve(listener)
	}()
	defer listener.Close()

	u.Path = openPath
	openURL := u.String()

	err = Open(openURL)
	if err != nil {
		return "", err
	}

	// XXX if server is not hit within a timeout, offer alternative

	select {
	case code := <-codeChan:
		return code, nil
	case err := <-errChan:
		return "", err
	}
}
