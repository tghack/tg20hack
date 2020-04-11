package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type HttpMux struct {
	Key string
    RemoteHost string
	W   http.ResponseWriter
}

func redirectSession(mux HttpMux) {
	mux.W.Header().Set("Location", "/" + create(mux.RemoteHost))
	mux.W.WriteHeader(http.StatusSeeOther)
}

var restartFile []byte

func (mux HttpMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux.W = w
    mux.RemoteHost = r.Header.Get("X-Forwarded-For")

    if len(mux.RemoteHost) == 0 {
        return
    }

	trimmedPath := strings.Trim(r.URL.Path, "/")
	splitted := strings.Split(trimmedPath, "/")

	if len(splitted) > 0 {
		mux.Key = splitted[0]
	}


	if validate(mux.Key) {
		var newURL url.URL
		newURL.Scheme = "http"
		newURL.Host = "127.0.0.1"
		newURL.Path = "/" + strings.TrimLeft(strings.TrimPrefix(trimmedPath, mux.Key), "/")
		newURL.RawQuery = r.URL.RawQuery

		var req http.Request
		req.Body = r.Body
		req.Method = r.Method
		req.URL = &newURL
		req.Header = r.Header.Clone()
		req.Header.Set("Challenge-Instance", mux.Key)

		go func() {
			var cookieReq http.Request
			cookieReq.Method = http.MethodGet
			cookieReq.URL, _ = url.Parse("http://127.0.0.1/")
			cookieReq.Header = make(http.Header)
			cookieReq.Header.Set("Challenge-Instance", mux.Key)
			cookieReq.Header.Set("Cookie", fmt.Sprintf("flag=%s", CHALLENGE_FLAG))
			bResp, bErr := backendRequest(mux.Key, &cookieReq)
			if bErr == nil {
				bResp.Body.Close()
			}
		}()

		resp, err := backendRequest(mux.Key, &req)
		if err != nil {
			mux.W.WriteHeader(http.StatusOK)
			mux.W.Write(restartFile)
			return
		}

		for headerName, values := range resp.Header {
			for k, v := range values {
				if k == 0 {
					w.Header().Set(headerName, v)
				} else {
					w.Header().Add(headerName, v)
				}
			}
		}

		w.WriteHeader(resp.StatusCode)
		io.CopyN(w, resp.Body, MAX_BODY_SIZE)
	} else {
		if strings.Contains(strings.ToLower(trimmedPath), "favicon") {
			mux.W.WriteHeader(http.StatusNotFound)
			mux.W.Write([]byte(http.StatusText(http.StatusNotFound)))
		} else {
			redirectSession(mux)
		}
	}
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

	listing := make([]string, 0, 0)
	listing, err = filepath.Glob("/hack/firecracker/*/*")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, v := range listing {
		if strings.HasSuffix(strings.ToLower(v), ".sock") || strings.HasSuffix(strings.ToLower(v), ".cfg") {
			os.Remove(v)
		}
	}

	restartFile, err = ioutil.ReadFile("/hack/restart.html")
	if err != nil {
		fmt.Println(err)
		return
	}

	var mux HttpMux
	http.ListenAndServe(fmt.Sprintf(":%d", HTTP_PORT), mux)
}
