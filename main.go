package main

import (
	//"html/template"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

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
	CookieKey string
	SessionKey string
	GoogleClientID string
	GoogleClientSecret string
	BindAddr string
}

var cfg config
var templates = template.Must(template.ParseFiles("assets/templates/providers.tmpl"))

func main() {

	cfg = config {
		BindAddr: ":3100",
		CookieKey: "NpEPi8pEjKVjLGJ6aYCS+VTCzi6BUuDzU0wrwXyf5uDPArtlofn2AG6aTMiPmN32909rsEWMNqJqhIVPGP3Exg==",
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

	cookieStoreKey, _ := base64.StdEncoding.DecodeString(cfg.CookieKey)
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(cfg.SessionKey)

	cookieStore = securecookie.New(cookieStoreKey, nil)
	sessionStore = sessions.NewCookieStore(sessionStoreKey)

	// Configure Authboss
	ab.RootURL = "http://localhost:3100"
	ab.MountPath = "/auth"
	//ab.Storer = database
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

	stack := alice.New(logger, ab.ExpireMiddleware).Then(pat)

	log.Printf("Listening on %s", cfg.BindAddr)
	err := http.ListenAndServe(cfg.BindAddr, stack)
	if err != nil {
		log.Fatal(err)
	}
}

func discourseSSO(w http.ResponseWriter, req *http.Request) {

	// XXX Do we get the original requiest, which includes the return
	// XXX URL, from the oauth2 state, or session?

	// If the user is not signed in, show the selection page.
	// Once the authentication is complete, the process re-directs
	// here with the original Discourse request

	currentUserName := ""
	currentEmail := ""
	//currentPicture := ""
	currentUID := ""
	//isAdmin := false

	_ = currentUserName
	_ = currentEmail
	_ = currentUID

	userInter, err := ab.CurrentUser(w, req)
	if userInter != nil && err == nil {

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

		w.WriteHeader(201)
		w.Write([]byte(currentUserName))

	} else {
		templates.ExecuteTemplate(w, "providers.tmpl", nil)
	}
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
