package oauth

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleProvider struct {
	oauthStateString  string
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

func (g *googleProvider) GetUserInfo(r *http.Request) ([]byte, error) {
	state, code := r.FormValue("state"), r.FormValue("code")
	if state != g.oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := g.googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" +
		token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return b, nil
}
