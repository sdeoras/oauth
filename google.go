package oauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/oauth2/google"

	"golang.org/x/oauth2"
)

// GoogleAuthContent is the struct in which we can marshal the data sent by google
// after successful authorization.
type GoogleAuthContent struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Link          string `json:"link"`
	Picture       string `json:"picture"`
}

func (c *GoogleAuthContent) Unmarshal(b []byte) error {
	return json.Unmarshal(b, c)
}

// googleProvider implements Provider interface
type googleProvider struct {
	oauthStateString  string
	googleOauthConfig *oauth2.Config
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

// Url to make http call to in order to obtain authorization
func (g *googleProvider) Url() string {
	return g.googleOauthConfig.AuthCodeURL(g.oauthStateString)
}

// GetUserInfo validates the response from google autho provider service and
// returns a byte buffer that can be json unmarshaled into a struct.
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
