package utils

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
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
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		panic(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		os.Stderr.WriteString(err.Error())
		return -1, ""
	}

	defer resp.Body.Close()
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
