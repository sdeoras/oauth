package oauth

// Provider provides a URL to redirect for oauth
type Provider interface {
	Url() string
}
