package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
var googleOauthConfig = &oauth2.Config{
	RedirectURL: "http://127.0.0.1:8000/oauth/corepass/callback",
	ClientID: "toktokey_local",
	ClientSecret: "OAISunclao9s8cp0nas9cpas",
	Scopes:       []string{"openid", "offline"},
	Endpoint:     oauth2.Endpoint{
		AuthURL: "https://hydra-stage.corepass.net/oauth2/auth",
		TokenURL: "https://hydra-stage.corepass.net/oauth2/token",
		AuthStyle: oauth2.AuthStyleInParams,
	},
}

var state string

const oauthGoogleUrlAPI = "https://hydra-stage.corepass.net/userinfo"
//const oauthGoogleUrlAPI = "https://hydra-stage.corepass.net/oauth2/token"

func oauthGoogleLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState cookie
	state = generateStateOauthCookie(w)

	/*
	AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must always provide a non-empty string and
	validate that it matches the state query parameter on your redirect callback.
	*/
	u := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func oauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	//oauthState, err := r.Cookie("state")

	log.Printf("state: %v\ncallback_state: %v",state, r.FormValue("state"))

	if r.FormValue("state") != state {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	state = ""

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var cui CorepassUserInfoResponse
	if err := json.Unmarshal(data, &cui); err != nil {
		log.Printf("%v",err)
	}

	// GetOrCreate User in your db.
	// Redirect or response with a token.
	// More code .....
	fmt.Fprintf(w, "UserInfo Raw: %s\n", data)
	fmt.Fprintf(w, "UserInfo: %s\n", cui)

//	kycRequest := KYCUserInfoRequest{
//		User: "0x2794c4b2ca6a8e595a62558fccf30238b75cb560",
//		Names: []string{"IDCardFullName", "IDCardDob"},
//		Callback: "http://127.0.0.1:8000/kyc/corepass/callback",
//}

	body, _ := json.Marshal(map[string]interface{}{
		"user":"0x35d3E98f7eb4dc8DD9dbD4cEbd8C275aAf913Ae9",
		"names":[]string{"IDCardFullName", "IDCardDob"},
		"callback":"http://127.0.0.1:8000/oauth/corepass/callback",
	})

	req, err := http.NewRequest("POST", "https://hydra-stage.corepass.net/kyc/isverified", bytes.NewBuffer(body))

	client := &http.Client{}
	resp, _ := client.Do(req)

	var kycResponse KYCIsVerifiedResponse
	if err := json.NewDecoder(resp.Body).Decode(&kycResponse); err != nil {
		log.Printf("%v",err)
	}

	defer resp.Body.Close()

	log.Printf("kycResponse: %v",kycResponse)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	bearer := "Bearer " + token.AccessToken

	req, err := http.NewRequest("GET", oauthGoogleUrlAPI, nil)

	req.Header.Add("Authorization", bearer)

	client := &http.Client{}

	response, err := client.Do(req)

	//response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

type CorepassUserInfoResponse struct {
	Sub string `json:"sub"`
}


type KYCUserInfoRequest struct {
	User string `json:"user"`
	Names []string `json:"names"`
	Callback string `json:"callback"`
}

type KYCUserInfoResponse struct {
	User string `json:"user"`
	Infos struct{
		IDCardFullName string `json:"IDCardFullName"`
	}`json:"infos"`
}

type KYCIsVerifiedResponse struct {
	Verifieds []string `json:"verifieds"`
	Unverifieds []string `json:"unverifieds"`
}