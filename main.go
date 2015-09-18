package main

import (
	//"html/template"
	"encoding/base64"
	"log"
	"html/template"
	"net/http"
    "os"
    "fmt"

	"github.com/gorilla/pat"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"
	"golang.org/x/oauth2"
	"gopkg.in/authboss.v0"
	aboauth2 "gopkg.in/authboss.v0/oauth2"
)

// globals
var ab = authboss.New()
var database = NewMemStorer()

type ProviderInfo struct {
    Name string
}

var templates = template.Must(template.ParseFiles("assets/templates/providers.tmpl"))

func main() {

	cookieStoreKey, _ := base64.StdEncoding.DecodeString("NpEPi8pEjKVjLGJ6kYCS+VTCzi6BUuDzU0wrwXyf5uDPArtlofn2AG6aTMiPmN3C909rsEWMNqJqhIVPGP3Exg==")
	sessionStoreKey, _ := base64.StdEncoding.DecodeString("AbfYwmmt8UCwUuhd9qvfNA9UCuN1cVcKJN1ofbiky6xCyyBj20whe40rJa3Su0WOWLWcPpO1taqJdsEI/65+JA==")

	cookieStore = securecookie.New(cookieStoreKey, nil)
	sessionStore = sessions.NewCookieStore(sessionStoreKey)

	// Configure Authboss
	ab.RootURL = "http://localhost:3100"
	ab.MountPath = "/auth"
	ab.Storer = database
	ab.OAuth2Storer = database

	ab.OAuth2Providers = map[string]authboss.OAuth2Provider{
		"google": authboss.OAuth2Provider{
			OAuth2Config: &oauth2.Config{
				ClientID:     "451002691710-h1mcjlqe0bfacdiq27kj3me5m02riu8k.apps.googleusercontent.com",
				ClientSecret: "x0gmxkQMubibAKS9aN_9bYJi",
				Scopes:       []string{"profile", "email"},
				Endpoint:     aboauth2.GoogleEndpoint,
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

	// Routing
	pat := pat.New()
	pat.PathPrefix("/auth").Handler(ab.NewRouter())
	pat.Path("/discourse").Methods("GET").HandlerFunc(discourseSSO)

	stack := alice.New(logger, ab.ExpireMiddleware).Then(pat)

	log.Printf("Listening on %s", ":3100")
	err := http.ListenAndServe(":3100", stack)
	if err != nil {
		log.Fatal(err)
	}
}

func discourseSSO(w http.ResponseWriter, req *http.Request) {

	//p := &ProviderInfo{ Name : "google"}
	//t, _ := template.ParseFiles("providers.tmpl")
	//t.Execute(w, template.HTML(`<b>World</b>`))
	templates.ExecuteTemplate(w, "providers.tmpl", nil)
    //data := layoutData(w, req)
    //r.HTML(w, http.StatusOK, "index", "{a:123}")
    //w.Write([]byte("Invalid ID or name"))
    //w.WriteHeader(400)
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
