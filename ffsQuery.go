package ffs

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

//Structs for FFS Queries
type Query struct {
	Groups      []Group `json:"groups"`
	GroupClause string  `json:"groupClause,omitempty"`
	PgNum       int     `json:"pgNum,omitempty"`
	PgSize      int     `json:"pgSize,omitempty"`
	PgToken     *string `json:"pgToken,omitempty"`
	SrtDir      string  `json:"srtDir,omitempty"`
	SrtKey      string  `json:"srtKey,omitempty"`
}

type Group struct {
	Filters      []SearchFilter `json:"filters"`
	FilterClause string         `json:"filterClause,omitempty"`
}

type SearchFilter struct {
	Operator string `json:"operator"`
	Term     string `json:"term"`
	Value    string `json:"value"`
}

type QueryProblem struct {
	BadFilter   SearchFilter `json:"badFilter,omitempty"`
	Description string       `json:"description,omitempty"`
	Type        string       `json:"type,omitempty"`
}

func ExecQuery(authData AuthData, ffsURI string, query Query) (*http.Response, error) {
	//Validate jsonQuery is valid JSON
	ffsQuery, err := json.Marshal(query)
	if err != nil {
		return nil, errors.New("jsonQuery is not in a valid json format")
	}

	//Make sure authData token is not ""
	if authData.Data.V3UserToken == "" {
		return nil, errors.New("authData cannot be nil")
	}

	//Query ffsURI with authData API token and jsonQuery body
	req, err := http.NewRequest("POST", ffsURI, bytes.NewReader(ffsQuery))

	//Handle request errors
	if err != nil {
		return nil, err
	}

	//Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "v3_user_token "+authData.Data.V3UserToken)

	//Get Response
	resp, err := http.DefaultClient.Do(req)

	//Handle response errors
	if err != nil {
		return nil, err
	}

	//defer body close
	defer resp.Body.Close()

	//Make sure http status code is 200
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Error with gathering file events POST: " + resp.Status)
	}

	return resp, nil
}
