package utils

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"unicode/utf8"
)

func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// HTTPRequest Send an HTTP request
func HTTPRequest(method string, url string, data string) (statusCode int, responseBody string) {
	client := &http.Client{}

	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		panic(err)
	}

	resp, _ := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	return resp.StatusCode, string(body)
}

func TrimLastChar(s string) string {
	r, size := utf8.DecodeLastRuneInString(s)
	if r == utf8.RuneError && (size == 0 || size == 1) {
		size = 0
	}
	return s[:len(s)-size]
}
