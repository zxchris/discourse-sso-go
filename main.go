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

type ssoPayload struct {
	nonce string
	email string
	external_id string
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
	pat.PathPrefix("/images").Methods("GET").Handler(http.FileServer(http.Dir("/assets/images/")))

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

		var payload = ssoPayload {
			email: currentEmail,
			external_id: currentUID,
		}
		var signature = base64.StdEncoding.encode_base64( ssoPayload )

		w.WriteHeader(201)
		w.Write([]byte(signature))

	} else {
		templates.ExecuteTemplate(w, "providers.tmpl", nil)
	}
}

// {
//    # Validate SSO signature
//    #
//    my $signature = $self->param('sig');
//    my $payload   = $self->param('sso');
//
//    my $secret    = $self->config->{discourse}->{sso_secret};
//    my $check_sig = hmac_sha256_hex( $payload, $secret );
//
//    return $self->render( json => { error => "Invalid request"}, status => 401 ) unless $check_sig eq $signature;
//
//    my $email = $self->user_email;
//    my $id    = $self->user_id;
//
//    # Decode the SSO payload
//    my $req = Mojo::URL->new();
//    $req->query( decode_base64( $payload ) );
//    my $nonce  = $req->query->param('nonce');
//    my $return = $req->query->param('return_sso_url');
//
//    $nonce   =~ s/^nonce=//; # Strip the nonce= off the front
//
//    # Use the configured return URL, falling back to the SSO payload provided
//    my $url = Mojo::URL->new( $self->config->{discourse}->{sso_callback_url} || $return );
//
//    my $username;
//    $_ = $self->user_email;
//    s/(\w+?)\@/$username = $1/e; # Use first part of email as username
//
//    $url->query(nonce    => $nonce,
//                #name     => '',
//                #username => $username,
//                email     => $self->user_email,
//                external_id => $self->user_id
//               );
//
//
//    $payload = encode_base64( $url->query->to_string );
//
//    $signature  = hmac_sha256_hex( $payload, $secret );
//
//    $url->query( sso => $payload, sig => $signature );
//
//    return $self->redirect_to( $url->to_string );
//}

    

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
