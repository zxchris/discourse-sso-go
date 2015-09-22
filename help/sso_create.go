package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/url"
	"os"
)

var hmac_key []byte

func main() {

	if v := os.Getenv("HMAC_256_SECRET"); len(v) > 0 {
		hmac_key, _ = base64.StdEncoding.DecodeString(v)
	}

	u, _ := url.Parse("")
	q := u.Query()
	q.Set("return", "http://www.zxdesign.info")
	q.Set("nonce", "thisismynoncevalue")
	log.Println(q)

	var payload = base64.URLEncoding.EncodeToString([]byte(q.Encode()))
	log.Printf("%s\n", payload)

	u, _ = url.Parse("http://localhost:3100/discourse")
	q = u.Query()
	q.Set("sso", payload)
	q.Set("sig", hex.EncodeToString(getSignature(payload)))
	u.RawQuery = q.Encode()

	log.Println(u)
}

func getSignature(payload string) []byte {

	mac := hmac.New(sha256.New, hmac_key)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// end
