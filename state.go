package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/base64"
	"errors"
	"io"
	"log"
)

func EncodeState(v interface{}) (string, error) {

	stateJson, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	log.Println(v)

	log.Printf("first json: '%s'\n", string(stateJson))

	cipher, err := encrypt(cfg.AESKey, stateJson)
	if err != nil {
		log.Printf("Error producing cipher")
		return "", err
	}

	res := base64.URLEncoding.EncodeToString(cipher)

	return res, nil
}

func DecodeState( state string, target interface{}) error {

	cipher, _ := base64.URLEncoding.DecodeString(state)

	text, err := decrypt(cfg.AESKey, cipher)
	if err != nil {
		log.Printf("Error decrypting cipher")
		return err
	}

	json.Unmarshal(text,target)
	return nil
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return text, nil
}
