package main

import (
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"gopkg.in/authboss.v0"
)

var nextUserID int

type User struct {
	ID   int
	Name string

	// Auth
	//Email    string
	//Password string

	// OAuth2
	Oauth2Uid      string
	Oauth2Provider string
	Oauth2Token    string
	Oauth2Refresh  string
	Oauth2Expiry   time.Time

	Email         string
	GooglePicture string
	GoogleName    string
	GoogleLink    string

	// Confirm
	//ConfirmToken string
	//Confirmed    bool

	// Lock
	//AttemptNumber int64
	//AttemptTime   time.Time
	//Locked        time.Time

	// Recover
	//RecoverToken       string
	//RecoverTokenExpiry time.Time

	// Remember is in another table
}

type MemStorer struct {
	Users  map[string]User
	Tokens map[string][]string
}

func NewMemStorer() *MemStorer {
	return &MemStorer{
		Users:  make(map[string]User),
		Tokens: make(map[string][]string),
	}
}

func (s MemStorer) Create(key string, attr authboss.Attributes) error {
	var user User
	if err := attr.Bind(&user, true); err != nil {
		return err
	}

	user.ID = nextUserID
	nextUserID++

	s.Users[key] = user
	//fmt.Println("Create")
	//spew.Dump(s.Users)
	return nil
}

func (s MemStorer) Put(key string, attr authboss.Attributes) error {
	return s.Create(key, attr)
}

func (s MemStorer) Get(key string) (result interface{}, err error) {
	user, ok := s.Users[key]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	return &user, nil
}

func (s MemStorer) PutOAuth(uid, provider string, attr authboss.Attributes) error {
	return s.Create(uid+provider, attr)
}

func (s MemStorer) GetOAuth(uid, provider string) (result interface{}, err error) {
	user, ok := s.Users[uid+provider]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	return &user, nil
}

func (s MemStorer) AddToken(key, token string) error {
	s.Tokens[key] = append(s.Tokens[key], token)
	fmt.Println("AddToken")
	spew.Dump(s.Tokens)
	return nil
}

func (s MemStorer) DelTokens(key string) error {
	delete(s.Tokens, key)
	fmt.Println("DelTokens")
	spew.Dump(s.Tokens)
	return nil
}

func (s MemStorer) UseToken(givenKey, token string) error {
	toks, ok := s.Tokens[givenKey]
	if !ok {
		return authboss.ErrTokenNotFound
	}

	for i, tok := range toks {
		if tok == token {
			toks[i], toks[len(toks)-1] = toks[len(toks)-1], toks[i]
			s.Tokens[givenKey] = toks[:len(toks)-1]
			return nil
		}
	}

	return authboss.ErrTokenNotFound
}
