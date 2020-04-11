package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

var serverStartTime int64 = time.Now().Unix()

func expired(timeStamp int64) bool {
	var expiry int64 = time.Now().Unix()
	return (((timeStamp + timeout) < expiry) || (timeStamp < serverStartTime))
}

func readyForDeletion(timeStamp int64) bool {
	var expiry int64 = time.Now().Unix()
	// to prevent the db from beeing deleted while written to.
	return (((timeStamp + 60 + timeout) < expiry) || (timeStamp < serverStartTime))
}

func createHtmlFilepath(file string) string {
	return "/server/html/" + file
}

func clean() {
	for {
		time.Sleep(10 * time.Second)
		cleanFiles()
	}
}

// clear old db files
func cleanFiles() {
	files, err := ioutil.ReadDir("/server/db")

	if err != nil {
		fmt.Println(err)
		return
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		var pathToFile string = createDBFilepath(file.Name())
		var timeStamp int64
		var splitted []string = strings.Split(file.Name(), "x")

		if len(splitted) == 2 {
			timeStamp, err = strconv.ParseInt(splitted[0], 16, 64)
			if err != nil {
				fmt.Println(err)
			}
		}

		// if session has expired
		if readyForDeletion(timeStamp) {
			err = os.Remove(pathToFile)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}
