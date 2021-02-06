package ffs

import (
	"log"
	"testing"
)

func TestGetAuthData(t *testing.T) {
	authData, err := GetAuthData(authUri, username, password)

	if err != nil {
		t.Error(err)
	}

	if authData.Error != "" {
		t.Error(authData.Error)
	}

	log.Println("Warnings: " + authData.Warnings)
	log.Println("Auth Token: " + authData.Data.V3UserToken)
}