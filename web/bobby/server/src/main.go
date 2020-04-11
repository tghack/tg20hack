package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const cookieName string = "id"

var listen string = ":4000"

const token string = "TG20{bobby_knows_his_sql}"
const timeout int64 = 500

var loginFile []byte
var passwordFile []byte
var cssFile []byte
var timeoutFile []byte

func loadHtml(file string) []byte {
	fileContent, err := ioutil.ReadFile(createHtmlFilepath(file))

	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	return fileContent
}

func main() {
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}

	fmt.Println("Listen: " + listen)
	fmt.Println("User = " + dbUser)
	fmt.Println("Pass = " + dbPassword + "\n")
	go clean()

	loginFile = loadHtml("login.html")
	passwordFile = loadHtml("password.html")
	cssFile = loadHtml("style.css")
	timeoutFile = loadHtml("timeout.html")

	http.HandleFunc("/", defaultHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/timeout", timeoutHandler)
	http.HandleFunc("/password", passwordHandler)
	http.HandleFunc("/style", styleHandler)
	http.HandleFunc("/start", cookieHandler)

	http.ListenAndServe(listen, nil)
}
