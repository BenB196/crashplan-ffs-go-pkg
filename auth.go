package ffs

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

// Code42 Auth

// AuthData Structs of Crashplan FFS API Authentication Token Return
type AuthData struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error,omitempty"`
	Warnings    string `json:"warnings,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   *int   `json:"expires_in,omitempty"`
}

/*
GetAuthData - Function to get the Authentication data (mainly the authentication token) which will be needed for the rest of the API calls
The authentication token is good for up to 1 hour before it expires
*/
func GetAuthData(uri string, username string, password string) (*AuthData, error) {
	//Build HTTP GET request
	req, err := http.NewRequest("POST", uri, nil)

	//Return nil and err if Building of HTTP GET request fails
	if err != nil {
		return nil, err
	}

	//Set Basic Auth Header
	req.SetBasicAuth(username, password)
	//Set Accept Header
	req.Header.Set("Accept", "application/json")

	//Make the HTTP Call
	resp, err := http.DefaultClient.Do(req)

	//Return nil and err if Building of HTTP GET request fails
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	//Return err if status code != 200
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Error with Authentication Token GET: " + resp.Status)
	}

	//Create AuthData variable
	var authData AuthData

	respData := resp.Body

	responseBytes, _ := ioutil.ReadAll(respData)

	if strings.Contains(string(responseBytes), "Service Under Maintenance") {
		return nil, errors.New("error: auth api service is under maintenance")
	}

	//Decode the resp.Body into authData variable
	err = json.Unmarshal(responseBytes, &authData)

	//Return nil and err if decoding of resp.Body fails
	if err != nil {
		return nil, err
	}

	//Return AuthData
	return &authData, nil
}
