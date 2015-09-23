package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/zxchris/discourse-sso-go/assets"
	"github.com/zxchris/discourse-sso-go/static"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"gopkg.in/unrolled/render.v1"

	"github.com/gorilla/pat"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/authboss.v0"
	aboauth2 "gopkg.in/authboss.v0/oauth2"
)

// globals
var ab = authboss.New()
var database = NewMemStorer()

type ProviderInfo struct {
	Name string
}

type googleProfile struct {
	Name    string
	Picture string
	Link    string
}

type config struct {
	CookieKey          string
	SessionKey         string
	GoogleClientID     string
	GoogleClientSecret string
	BindAddr           string
	HMAC256Secret      []byte
	AESKey             []byte
}

type SSORequest struct {
	Nonce     string
	ReturnURL string
}

var cfg config
var templates = template.Must(template.ParseFiles("assets/templates/providers.tmpl"))

type staticConfig struct {
	Asset      func(string) ([]byte, error)
	AssetNames func() []string
}

var r = render.New(render.Options{
	Asset:      assets.Asset,
	AssetNames: assets.AssetNames,
})

func main() {

	cfg = config{
		BindAddr:   ":3100",
		CookieKey:  "NpEPi8pEjKVjLGJ6aYCS+VTCzi6BUuDzU0wrwXyf5uDPArtlofn2AG6aTMiPmN32909rsEWMNqJqhIVPGP3Exg==",
		SessionKey: "AbfYwmmt8UCwUuad9qvfNA9UCuN1cVcKJN1ofbiky6xCyyBj20whe40rJa3Su0W1WLWcPpO1taqJdsEI/65+Jg==",
	}

	if v := os.Getenv("BIND_ADDR"); len(v) > 0 {
		cfg.BindAddr = v
	}
	if v := os.Getenv("COOKIE_STORE_KEY"); len(v) > 0 {
		cfg.CookieKey = v
	}
	if v := os.Getenv("SESSION_STORE_KEY"); len(v) > 0 {
		cfg.SessionKey = v
	}
	if v := os.Getenv("GOOGLE_CLIENT_ID"); len(v) > 0 {
		cfg.GoogleClientID = v
	}
	if v := os.Getenv("GOOGLE_CLIENT_SECRET"); len(v) > 0 {
		cfg.GoogleClientSecret = v
	}
	if v := os.Getenv("HMAC_256_SECRET"); len(v) > 0 {
		cfg.HMAC256Secret, _ = base64.StdEncoding.DecodeString(v)
	}
	if v := os.Getenv("AES_KEY"); len(v) > 0 {
		cfg.AESKey, _ = base64.StdEncoding.DecodeString(v)
	}

	if len(cfg.AESKey) == 0 {
		log.Fatal("No AES_KEY environment variable set\n")
	}

	cookieStoreKey, _ := base64.StdEncoding.DecodeString(cfg.CookieKey)
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(cfg.SessionKey)

	cookieStore = securecookie.New(cookieStoreKey, nil)
	sessionStore = sessions.NewCookieStore(sessionStoreKey)

	// Configure Authboss
	ab.RootURL = "http://localhost:3100"
	ab.MountPath = "/auth"
	ab.OAuth2Storer = database

	ab.OAuth2Providers = map[string]authboss.OAuth2Provider{
		"google": authboss.OAuth2Provider{
			OAuth2Config: &oauth2.Config{
				ClientID:     cfg.GoogleClientID,
				ClientSecret: cfg.GoogleClientSecret,
				Scopes:       []string{"profile", "email"},
				Endpoint:     google.Endpoint,
			},
			Callback: aboauth2.Google,
		},
	}
	ab.XSRFName = "csrf_token"
	ab.XSRFMaker = func(_ http.ResponseWriter, r *http.Request) string {
		return nosurf.Token(r)
	}
	// Make sure login expires quickly, as we don't need or want to cache the
	// login for long (user info is stored in memory and linked to by a cookie.
	// If the server restarts, the cookie will be out of sync with the memory
	// store (now empty) and generate "User is unknown" error).
	// We're just acting as a proxy between Discourse and OAuth2, so holding onto
	// the login state is not necessary.
	ab.ExpireAfter = 5 // 5 Second expiry of login
	ab.Mailer = authboss.LogMailer(os.Stdout)
	ab.CookieStoreMaker = NewCookieStorer
	ab.SessionStoreMaker = NewCookieStorer

	if err := ab.Init(); err != nil {
		log.Fatal(err)
	}

	// Routing
	pat := pat.New()
	pat.PathPrefix("/auth").Handler(ab.NewRouter())
	pat.Path("/discourse").Methods("GET").HandlerFunc(discourseSSO)

	pat.PathPrefix("/images").Methods("GET").Handler(http.FileServer(http.Dir("/assets/images/")))

	var myconf = staticConfig{
		Asset:      assets.Asset,
		AssetNames: assets.AssetNames,
	}
	static.Register(myconf, pat)

	stack := alice.New(logger, ab.ExpireMiddleware).Then(pat)

	log.Printf("Listening on %s", cfg.BindAddr)
	err := http.ListenAndServe(cfg.BindAddr, stack)
	if err != nil {
		log.Fatal(err)
	}
}

func discourseSSO(w http.ResponseWriter, req *http.Request) {

	// If we get a decodable state parameter in the request, then
	// we have completed the authorisation round-trip, and thus can
	// inspect the user state and construct the Discourse return.

	ssor := &SSORequest{}

	state := req.FormValue("state")
	if state != "" {
		if err := DecodeState(state, ssor); err != nil {
			state = ""
		}
	}

	// Otherwise, create the encoded state and populate the OAuth2
	// provider selection template.

	if state == "" {
		if verifyRequest(req) != true {
			w.WriteHeader(400)
			w.Write([]byte("Invalid request"))
			return
		}
		ssor = decodeSSO(req)
		if ssor == nil {
			log.Printf("Cannot decode request")
			return
		}
	}

	log.Println(ssor)

	// If the user is not signed in, show the selection page.
	// Once the authentication is complete, the process re-directs
	// here with the original Discourse request encoded in an encrypted
	// state parameter.

	currentUserName := ""
	currentEmail := ""
	currentUID := ""
	//currentPicture := ""
	//isAdmin := false

	_ = currentUserName
	_ = currentEmail
	_ = currentUID

	userInter, err := ab.CurrentUser(w, req)

	// State is set, and we have user info, so we can return login info to Discourse
	if state != "" && userInter != nil && err == nil {

		user := userInter.(*User)

		if user.Name == "" && user.Oauth2Provider == "google" {
			log.Printf("NO USER\n")

			req, err := http.NewRequest("GET", "https://www.googleapis.com/userinfo/v2/me", nil)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte("Failed to create profile request"))
				return
			}
			req.Header.Set("Authorization", "Bearer "+user.Oauth2Token)

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte("Failed to read profile"))
				return
			}

			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte("Failed to read profile"))
				return
			}

			res.Body.Close()

			var prof googleProfile
			err = json.Unmarshal(b, &prof)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte("Failed to import profile"))
				return
			}

			user.Name = prof.Name
			user.GoogleName = prof.Name
			user.GooglePicture = prof.Picture
			user.GoogleLink = prof.Link
		}

		currentUID = userInter.(*User).Oauth2Uid + userInter.(*User).Oauth2Provider
		currentUserName = userInter.(*User).Name
		currentEmail = userInter.(*User).Email
		//currentPicture = userInter.(*User).GooglePicture
		//isAdmin = userInter.(*User).IsAdmin

		log.Printf("%+v\n", userInter)

		u, _ := url.Parse("")
		q := u.Query()
		q.Set("email", currentEmail)
		q.Set("external_id", currentUID)
		q.Set("name", currentUserName)
		q.Set("nonce", ssor.Nonce)

		var payload = base64.URLEncoding.EncodeToString([]byte(q.Encode()))
		log.Printf("%s\n", payload)

		u, _ = url.Parse(ssor.ReturnURL)
		q = u.Query()
		q.Set("sso", payload)
		q.Set("sig", hex.EncodeToString(getSignature(payload)))
		u.RawQuery = q.Encode()
		log.Println(u)

		// TODO Redirect here
		w.WriteHeader(201)
		w.Write([]byte(u.String()))

	} else {
		// When generating the Federated Login link in the template, encode the
		// Discourse SSO nonce and return URL into an encrypted state.
		state, err := EncodeState(*ssor)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("Cannot encode request state"))
			return
		}
		log.Printf("Encrypted state: '%s'\n", state)

		r.HTML(w, http.StatusOK, "providers", map[string]string{
			"State": state,
		})
	}
}

// returns ssoRequest and error state
func decodeSSO(req *http.Request) *SSORequest {

	query, err := base64.URLEncoding.DecodeString(req.FormValue("sso"))

	log.Printf("Request sso content: %s", string(query))

	if err != nil {
		return nil
	}
	log.Printf("Decodeing request...")
	q, err := url.ParseQuery(string(query))
	log.Println(q)

	ssor := &SSORequest{}

	if n, ok := q["nonce"]; ok {
		ssor.Nonce = n[0]
	}
	if n, ok := q["return"]; ok {
		ssor.ReturnURL = n[0]
	}

	//	ssor.Nonce = "This is a nonce"
	//	ssor.ReturnURL = "http://www.google.com"

	return ssor
}

func getSignature(payload string) []byte {

	mac := hmac.New(sha256.New, cfg.HMAC256Secret)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func verifyRequest(req *http.Request) bool {
	signature, err := hex.DecodeString(req.FormValue("sig"))
	payload := req.FormValue("sso")

	if err != nil || payload == "" {
		return false
	}
	newsig := getSignature(payload)
	//_ = newsig
	//_ = signature
	//return false
	return hmac.Equal(newsig, signature)
}

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n%s %s %s\n", r.Method, r.URL.Path, r.Proto)
		session, err := sessionStore.Get(r, sessionCookieName)
		if err == nil {
			fmt.Print("Session: ")
			first := true
			for k, v := range session.Values {
				if first {
					first = false
				} else {
					fmt.Print(", ")
				}
				fmt.Printf("%s = %v", k, v)
			}
			fmt.Println()
		}
		h.ServeHTTP(w, r)
	})
}

// end
