package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"net/http"
	"regexp"
	"strings"
)

type Salts struct {
	Error string 		`json:"error"`
	Salt string			`json:"salt"`
	Saltwebui string	`json:"saltwebui"`
}

type IPAddressRT struct {
	IPAddressRT string 	`json:"IPAddressRT"`
}

type IPFetch struct {
	Error string 		`json:"error"`
	Message string 		`json:"message"`
	Data IPAddressRT 		`json:"data"`
}

func getSessionId() string {
	sessionResp, _ := http.Get("http://192.168.87.1/api/v1/session/menu?_=1584707181191")

	cookieHeader := sessionResp.Header.Values("Set-Cookie")[0]

	r, _ := regexp.Compile("[a-zA-Z0-9]+;")

	extractedSessionId := r.FindString(cookieHeader)
	withoutSemicolon := strings.Trim(extractedSessionId, ";")

	return withoutSemicolon
}

func getPasswordSalts(sessionId string) Salts {
	reader := strings.NewReader("username=user&password=seeksalthash")
	cookieHeader := fmt.Sprintf("theme-value=css/theme/dark/; lang=en; PHPSESSID=%s", sessionId)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, "http://192.168.87.1/api/v1/session/login", reader)
	req.Header.Set("Cookie", cookieHeader)

	saltsResponse, _ := client.Do(req)

	salts := Salts{}

	err := json.NewDecoder(saltsResponse.Body).Decode(&salts)

	if err != nil {
		fmt.Println(err)
	}

	return salts
}

func login(password string, sessionId string) string {
	interpolatedString := fmt.Sprintf("username=user&password=%s", password)
	cookieHeader := fmt.Sprintf("theme-value=css/theme/dark/; lang=en; PHPSESSID=%s", sessionId)

	reader := strings.NewReader(interpolatedString)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, "http://192.168.87.1/api/v1/session/login", reader)
	req.Header.Set("Cookie", cookieHeader)

	loginResponse, _ := client.Do(req)

	// extract auth in header
	cookieResult := loginResponse.Header.Values("Set-Cookie")[0]

	r, _ := regexp.Compile("[a-zA-Z0-9]+;")

	extractedSessionId := r.FindString(cookieResult)
	withoutSemicolon := strings.Trim(extractedSessionId, ";")

	return withoutSemicolon
}

func doPbkdf2NotCoded(passwd string, saltLocal string) string {
	derivedKey := pbkdf2.Key([]byte(passwd), []byte(saltLocal), 1000, 16, sha256.New)
	str := hex.EncodeToString(derivedKey)
	return str
}

func authedRequest(url string, token string, sessionId string) *http.Response {
	//curl 'http://192.168.87.1/api/v1/dhcp/v4/1/IPAddressRT'
	//-H 'X-CSRF-TOKEN: f74eeef7bbcb74a80df9b8de75b972e5'
	//-H 'X-Requested-With: XMLHttpRequest'
	//-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36'
	//-H 'Cookie: theme-value=css/theme/dark/; lang=en; PHPSESSID=fer414sku5ji6np5qdc6ma49h3; auth=f74eeef7bbcb74a80df9b8de75b972e5'
	cookieHeader := fmt.Sprintf("theme-value=css/theme/dark/; lang=en; PHPSESSID=%s; auth=%s", sessionId, token)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-CSRF-TOKEN", token)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36")
	req.Header.Set("Cookie", cookieHeader)

	resp, _ := client.Do(req)

	return resp
}

func renewLease(token string, sessionId string) *http.Response {
	cookieHeader := fmt.Sprintf("theme-value=css/theme/dark/; lang=en; PHPSESSID=%s; auth=%s", sessionId, token)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, "http://192.168.87.1/", nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Referer", "http://192.168.87.1/")
	req.Header.Set("Accept-Language", "en-AU,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,da;q=0.6")
	req.Header.Set("If-None-Match", "\"4138254307\"")
	req.Header.Set("If-Modified-Since", "Fri, 30 Aug 2019 01:57:24 GMT")
	req.Header.Set("Cookie", cookieHeader)

	resp, _ := client.Do(req)

	return resp
}

func main() {
	sessionId := getSessionId()

	passwordSalts := getPasswordSalts(sessionId)

	firstRound := doPbkdf2NotCoded("ZwdbMwYR7SZw", passwordSalts.Salt)
	secondRound := doPbkdf2NotCoded(firstRound, passwordSalts.Saltwebui)

	token := login(secondRound, sessionId)

	renewLease(token, sessionId)

	ipResp := authedRequest("http://192.168.87.1/api/v1/dhcp/v4/1/IPAddressRT", token, sessionId)
	ips := IPFetch{}
	json.NewDecoder(ipResp.Body).Decode(&ips)


	fmt.Println(ips)
}
