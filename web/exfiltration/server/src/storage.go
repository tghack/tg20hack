package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

const KEY_TYPE_AUTH uint = 0x10
const KEY_TYPE_URL uint = 0x11

var urlSecret = make([]byte, 64, 64)
var authSecret = make([]byte, 64, 64)

var entries = make(map[string]string)
var mutex sync.Mutex

func init() {
	rand.Read(urlSecret)
	rand.Read(authSecret)
}

func set(key string, val string) {
	mutex.Lock()
	oldPosts, ok := entries[key]
	if ok {
		entries[key] = `<div style="border-style: none none solid none; border-width: thin; padding: 1em;">` + val + "</div>\n" + oldPosts
	} else {
		entries[key] = `<div style="border-style: none none none none; padding: 1em;">` + val + `</div>`
	}

	mutex.Unlock()
}
func get(key string) string {
	mutex.Lock()
	val, ok := entries[key]
	mutex.Unlock()
	if ok {
		return val
	}
	return ""
}

func validate(key string, keyType uint) bool {
	splitted := strings.Split(key, "-")
	if len(splitted) != 2 {
		return false
	}

	secret := urlSecret
	if keyType == KEY_TYPE_AUTH {
		secret = authSecret
	}

	h := hmac.New(sha256.New, secret)

	h.Write([]byte(splitted[0]))
	expected := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(splitted[1]))
}

func create() string {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	key := hex.EncodeToString(keyBytes)

	h := hmac.New(sha256.New, urlSecret)
	h.Write([]byte(key))
	return key + "-" + hex.EncodeToString(h.Sum(nil))
}

func createAuthToken(token string) string {
	splitted := strings.Split(token, "-")
	if len(splitted) != 2 {
		return ""
	}

	key := splitted[0]

	h := hmac.New(sha256.New, authSecret)
	h.Write([]byte(key))
	return key + "-" + hex.EncodeToString(h.Sum(nil))
}
