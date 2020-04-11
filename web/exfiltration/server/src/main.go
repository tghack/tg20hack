package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

const FLAG = "TG20{exfiltration_is_best_filtration}"
const BODY_SIZE = 8192

var htmlTemplate string
var scriptData string

type HttpMux struct{}

func (mux HttpMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.Trim(r.URL.Path, "/")

	splitted := strings.SplitAfter(key, "-")

	headless := false
	authenticated := false

	if len(splitted) == 2 {
		keyPrefix := splitted[0]
		for k, headers := range r.Header {
			if strings.EqualFold(k, "headless-auth") {
				headless = true
				for _, header := range headers {
					if validate(header, KEY_TYPE_AUTH) && strings.HasPrefix(header, keyPrefix) {
						authenticated = true
						break
					}
				}
			}
		}
	}

	if authenticated {
		w.Header().Set("Set-Cookie", "flag="+FLAG)
	}

	if strings.HasSuffix(key, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(scriptData))
		return
	}

	val := get(key)

	if strings.EqualFold(r.Method, "POST") {
		httpBody := make([]byte, BODY_SIZE)
		size, err := r.Body.Read(httpBody)

		if (err != nil) && (err != io.EOF) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
		val = string(httpBody[0:size:size])
	}

	if validate(key, KEY_TYPE_URL) {
		if strings.EqualFold(r.Method, "POST") {
			set(key, val)
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(http.StatusText(http.StatusOK)))
		} else {
			fmt.Println("This was a GET request")
			if headless {
				fmt.Printf("Headless request to %s\n", r.URL.Path)
			} else {
				if len(val) > 0 {
					cmd := exec.Command("node", "/hack/src/view.js", createAuthToken(key), "http://127.0.0.1:4001/"+key)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Env = append(os.Environ(), "NODE_PATH=/usr/lib/node_modules")

					err := cmd.Run()
					if err != nil {
						fmt.Println(err)
					}
					val = get(key)
				}
			}
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(strings.Replace(htmlTemplate, "{{data}}", val, 1)))
		}
	} else {
		w.Header().Set("Location", "/"+create())
		w.WriteHeader(http.StatusFound)
	}
}

func readFiles() bool {
	htmlBuf := make([]byte, BODY_SIZE)
	scriptBuf := make([]byte, BODY_SIZE)

	htmlFile, err := os.Open("/hack/src/index.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer htmlFile.Close()

	htmlCount, err := htmlFile.Read(htmlBuf)
	if (err != nil) && (err != io.EOF) {
		fmt.Println(err)
		return false
	}

	scriptFile, err := os.Open("/hack/src/script.js")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer scriptFile.Close()

	scriptCount, err := scriptFile.Read(scriptBuf)
	if (err != nil) && (err != io.EOF) {
		fmt.Println(err)
		return false
	}
	htmlTemplate = string(htmlBuf[0:htmlCount:htmlCount])
	scriptData = string(scriptBuf[0:scriptCount:scriptCount])
	return true
}

func main() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, addr := range addrs {
		fmt.Println(addr.String())
	}

	if readFiles() {
		var mux HttpMux
		http.ListenAndServe(":4001", mux)
	}
}
