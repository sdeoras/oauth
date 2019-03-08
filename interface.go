package oauth

import "net/http"

// Provider provides a URL to redirect for oauth
type Provider interface {
	Url() string
	GetUserInfo(r *http.Request) ([]byte, error)
}
