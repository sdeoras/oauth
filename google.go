package oauth

import (
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleProvider struct {
	oauthStateString string
	googleOauthConfig *oauth2.Config
}

func (g *googleProvider) Url() string {
	return g.googleOauthConfig.AuthCodeURL(g.oauthStateString)
}

func NewGoogleProvider(redirectURL, clientId, clientSecret string) Provider {
	g := new(googleProvider)
	g.oauthStateString = uuid.New().String()
	g.googleOauthConfig = &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	return g
}