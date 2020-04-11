package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	var id string = identifyTeam(w, r)

	// The id should never be this short
	if len(id) < 100 {
		return
	}

	w.Header().Add("Location", "/login")
	w.WriteHeader(303)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	id := identifyTeam(w, r)

	// The id should never be this short
	if len(id) < 100 {
		return
	}

	w.Header().Add("Content-Type", "text/html")
	w.Write(loginFile)

	r.ParseForm()
	data := r.PostForm

	if r.Method == "POST" {
		fmt.Printf("User: %s, Pass: %s\n", data.Get("user"), data.Get("pass"))
		if login(id, data.Get("user"), data.Get("pass")) {
			fmt.Println("Correct password!\n")
			w.Write([]byte(token))
		}
	}
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {
	var id string = identifyTeam(w, r)

	// The id should never be this short
	if len(id) < 100 {
		return
	}

	r.ParseForm()
	data := r.PostForm
	w.Header().Add("Content-Type", "text/html")
	status := ""
	if r.Method == "POST" {
		status = changePassword(id, data.Get("user"), data.Get("old_pass"), data.Get("new_pass"))
	}

	statusLine := strings.Replace(`<div class="line"><div class="right">{{status}}</div></div>`, "{{status}}", status, 1)
	if len(status) == 0 {
		statusLine = ""
	}

	w.Write([]byte(strings.Replace(string(passwordFile), "{{status}}", statusLine, 1)))
}

func styleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/css")
	w.Write(cssFile)
}

func timeoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.Write(timeoutFile)
}

func identifyTeam(w http.ResponseWriter, r *http.Request) string {
	var identifier string
	cookie, err := r.Cookie(cookieName)

	if err == nil {
		identifier = cookie.Value
	}

	if !validateID(identifier) {
		w.Header().Add("Location", "/timeout")
		w.WriteHeader(303)
		return "fail"
	}
	return identifier
}

func cookieHandler(w http.ResponseWriter, r *http.Request) {
	cookies := r.Cookies()
	var err error
	var identifier string

	for _, v := range cookies {
		if v.Name == cookieName {
			identifier = filter(v.Value)
			break
		}
	}

	if !validateID(identifier) {

		// Create new DB and redirect
		identifier, err = createID()

		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("Error 500: Internal server error."))
		} else {
			// cookie exists, only redirect
			createDB(identifier)
			var cookie string = cookieName + "=" + identifier + "; Max-Age=" + strconv.FormatInt(timeout, 10)

			w.Header().Add("Set-Cookie", cookie)
			w.Header().Add("Location", "/login")
			w.WriteHeader(303)
		}
	} else {
		w.Header().Add("Location", "/login")
		w.WriteHeader(303)
	}
}
