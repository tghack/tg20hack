package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const BODY_SIZE = 8192

var productTemplate string
var bankTemplate string
var storeTemplate string

type HttpMux struct {
	BankPage  string
	StorePage string
	Key       string
	Data      map[string]int64
	W         http.ResponseWriter
}

func redirectSession(mux HttpMux) {
	mux.W.Header().Set("Location", "/"+create()+"/bank")
	mux.W.WriteHeader(http.StatusSeeOther)
}

func (mux HttpMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux.W = w
	mux.Data = make(map[string]int64)

	if strings.EqualFold(r.Method, "post") {
		buf := make([]byte, BODY_SIZE, BODY_SIZE)
		bodySize, _ := r.Body.Read(buf)
		query, err := url.ParseQuery(string(buf[0:bodySize:bodySize]))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
			return
		}
		for k, v := range query {
			if len(v) >= 1 {
				if len(v[0]) < 15 {
					num, err := strconv.ParseInt(v[0], 10, 64)
					if err == nil {
						mux.Data[strings.ToLower(k)] = num
					}
				}
			}
		}
	}

	trimmedPath := strings.Trim(r.URL.Path, "/")
	splitted := strings.Split(trimmedPath, "/")

	if len(splitted) > 0 {
		mux.Key = splitted[0]
	}

	if validate(mux.Key) {
		mux.BankPage = "/" + mux.Key + "/bank"
		mux.StorePage = "/" + mux.Key + "/store"
	} else {
		redirectSession(mux)
		return
	}

	if strings.HasSuffix(trimmedPath, "bank") {
		mux.ServeBank()
	} else if strings.HasSuffix(trimmedPath, "store") {
		mux.ServeStore()
	}
}

func (mux HttpMux) ServeBank() {
	amountBorrow, okBorrow := mux.Data["borrow"]
	amountRepay, okRepay := mux.Data["repay"]

	if okRepay && okBorrow {
		mux.W.WriteHeader(http.StatusBadRequest)
		mux.W.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return
	}
	transactionFailed := false

	if okRepay {
		transactionFailed = !repay(mux.Key, amountRepay)
	}
	if okBorrow {
		transactionFailed = !borrow(mux.Key, amountBorrow)
	}

	replacements := make(map[string]string)
	page := bankTemplate
	replacements["{{action}}"] = mux.BankPage
	replacements["{{statement}}"] = bankStatement(mux.Key)
	replacements["{{error}}"] = ""
	replacements["{{store}}"] = mux.StorePage

	if transactionFailed {
		if okBorrow {
			if amountBorrow >= 0 {
				replacements["{{error}}"] = fmt.Sprintf("You can't borrow that amount of money. You can't have more than %d$ in debt.", MAX_DEBT)
			} else {
				replacements["{{error}}"] = "You can't borrow a negative amount of money."
			}
		}
		if okRepay {
			if amountRepay >= 0 {
				replacements["{{error}}"] = "Insufficient funds!"
			} else {
				replacements["{{error}}"] = "You can't repay a negative amount of money."
			}
		}
	}

	for k, v := range replacements {
		page = strings.Replace(page, k, v, 10)
	}

	mux.W.Write([]byte(page))
}

func (mux HttpMux) ServeStore() {
	sum, oksum := mux.Data["sum"]
	id, okid := mux.Data["id"]
	transactionFailed := false

	var product Product
	product.Available = false

	if oksum && okid {
		transactionFailed = true
		if id < int64(len(products)) {
			product = products[id]
		}
		if product.Available {
			if product.Price == sum {
				transactionFailed = !buy(mux.Key, sum)
			}
		} else {
			transactionFailed = !buy(mux.Key, sum)
		}
	}

	page := storeTemplate
	replacements := make(map[string]string)
	replacements["{{action}}"] = mux.StorePage
	replacements["{{bank}}"] = mux.BankPage

	if transactionFailed {
		replacements["{{event}}"] = "Insufficient funds!"
	} else {
		replacements["{{event}}"] = ""
		if product.Available {
			replacements["{{event}}"] = product.Message
		}
	}

	renderedProducts := ""
	for k, v := range products {
		if v.Available {
			current := productTemplate
			current = strings.Replace(current, "{{action}}", mux.StorePage, 10)
			current = strings.Replace(current, "{{price}}", strconv.FormatInt(v.Price, 10), 10)
			current = strings.Replace(current, "{{name}}", v.Name, 10)
			current = strings.Replace(current, "{{id}}", strconv.FormatInt(int64(k), 10), 10)
			renderedProducts += current
		}
	}

	replacements["{{products}}"] = renderedProducts

	for k, v := range replacements {
		page = strings.Replace(page, k, v, 10)
	}
	mux.W.Write([]byte(page))
}

func readFiles() bool {
	bankBuf := make([]byte, BODY_SIZE)
	storeBuf := make([]byte, BODY_SIZE)
	productBuf := make([]byte, BODY_SIZE)

	productFile, err := os.Open("/hack/src/product.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer productFile.Close()

	productCount, err := productFile.Read(productBuf)
	if (err != nil) && (err != io.EOF) {
		fmt.Println(err)
		return false
	}

	bankFile, err := os.Open("/hack/src/bank.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer bankFile.Close()

	bankCount, err := bankFile.Read(bankBuf)
	if (err != nil) && (err != io.EOF) {
		fmt.Println(err)
		return false
	}

	storeFile, err := os.Open("/hack/src/store.html")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer storeFile.Close()

	storeCount, err := storeFile.Read(storeBuf)
	if (err != nil) && (err != io.EOF) {
		fmt.Println(err)
		return false
	}
	productTemplate = string(productBuf[0:productCount:productCount])
	bankTemplate = string(bankBuf[0:bankCount:bankCount])
	storeTemplate = string(storeBuf[0:storeCount:storeCount])
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
		http.ListenAndServe(":4004", mux)
	}
}
