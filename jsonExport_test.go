package ffs

import (
	"log"
	"testing"
)

func TestGetJsonFileEvents(t *testing.T) {
	authData, err := GetAuthData(authUri, username, password)

	if err != nil {
		t.Error(err)
	}

	if authData.Error != "" {
		t.Error(authData.Error)
	}

	log.Println("Warnings: " + authData.Warnings)
	log.Println("Auth Token: " + authData.Data.V3UserToken)

	jsonFileEvents, nextPgToken, err := GetJsonFileEvents(*authData, ffsUri, jsonQuery, "")

	if err != nil {
		t.Error(err)
	}

	log.Println(nextPgToken)

	if jsonFileEvents != nil && len(*jsonFileEvents) > 0 {
		for _, event := range *jsonFileEvents {
			log.Println(event)
		}
	}
}
