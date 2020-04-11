package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

var commonSecret []byte = random()

// password in db
var dbPassword string = hex.EncodeToString(random())
var dbUser string = hex.EncodeToString(random())

func random() (secret []byte) {
	secret = make([]byte, 64)
	rand.Read(secret)
	return secret
}

func createID() (string, error) {
	var str string
	var userSecret string = hex.EncodeToString(random())
	var currentTime int64 = time.Now().Unix()
	correctHash, err := createHash(currentTime, userSecret)
	var userString string = strconv.FormatInt(currentTime, 16) + "x" + userSecret + "x"
	str = userString + hex.EncodeToString(correctHash)
	return str, err
}

// converts to lower case, and removes symbols not in a-z,0-9
func filter(txt string) (filtered string) {
	for _, v := range txt {
		var next rune = v
		//convert to lower case
		if (v > 64) && (v < 91) {
			next = v + 32
		}
		if ((next > 47) && (next < 58)) || ((next > 96) && (next < 123)) {
			filtered += string(next)
		}
	}
	return filtered
}

func validateID(txt string) bool {
	if len(txt) > 250 {
		return false
	}

	var parts []string = strings.Split(txt, "x")

	// wrongly formatted
	if len(parts) != 3 {
		return false
	}

	var timeStamp int64
	var userSecret string
	timeStamp, err := strconv.ParseInt(parts[0], 16, 64)
	if (err != nil) || expired(timeStamp) {
		return false
	}

	userSecret = parts[1]
	correctHash, err := createHash(timeStamp, userSecret)
	if err != nil {
		return false
	}

	var userHash []byte
	userHash, err = hex.DecodeString(parts[2])

	if err != nil {
		return false
	}

	return hmac.Equal(userHash, correctHash)
}

func createHash(timeStamp int64, secret string) ([]byte, error) {
	var userString string = strconv.FormatInt(timeStamp, 16) + secret
	sum := hmac.New(sha256.New, commonSecret)
	_, err := sum.Write([]byte(userString))
	return sum.Sum(nil), err
}
