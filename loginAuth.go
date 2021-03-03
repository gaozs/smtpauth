package smtpauth

import (
	"bytes"
	"errors"
	"net/smtp"
)

type loginAuth struct {
	username, password []byte
}

// LoginAuth generate a smtp auth which support login auth
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{[]byte(username), []byte(password)}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// Must have TLS
	if !server.TLS {
		return "", nil, errors.New("unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if bytes.Equal(fromServer, []byte("Username:")) {
		return a.username, nil
	}
	if bytes.Equal(fromServer, []byte("Password:")) {
		return a.password, nil
	}
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}
