//Packages provide a module for using the Code42 Crashplan FFS API
package ffs

import (
	"encoding/json"
	"errors"
	"net/http"
)

//The main body of a file event record
type FileEvent struct {
	EventId						string			`json:"eventId"`
	EventType					string			`json:"eventType"`
	EventTimestamp				string			`json:"eventTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	InsertionTimestamp			string			`json:"insertionTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	FilePath					string			`json:"filePath"`
	FileName					string			`json:"fileName"`
	FileType					string			`json:"fileType"`
	FileCategory				string			`json:"fileCategory"`
	FileSize					int				`json:"fileSize"`
	FileOwner					string			`json:"fileOwner,omitempty"`
	Md5Checksum					string			`json:"md5Checksum,omitempty"`
	Sha256Checksum				string			`json:"sha256Checksum,omitempty"`
	CreatedTimestamp			string			`json:"createdTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	ModifyTimestamp				string			`json:"modifyTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	DeviceUserName				string			`json:"deviceUserName"`
	DeviceStatus				string			`json:"deviceStatus,omitempty"`
	OsHostName					string			`json:"osHostName"`
	DomainName					string			`json:"domainName"`
	PublicIpAddress				string			`json:"publicIpAddress,omitempty"`
	PrivateIpAddresses			[]string		`json:"privateIpAddresses"` //Array of IP address strings
	DeviceUid					string			`json:"deviceUid"`
	UserUid						string			`json:"userUid"`
	Actor						string			`json:"actor,omitempty"`
	DirectoryId					[]string		`json:"directoryId,omitempty"` //An array of something, I am not sure
	Source						string			`json:"source"`
	Url							string			`json:"url,omitempty"`
	Shared						string			`json:"shared,omitempty"`
	SharedWith					[]string		`json:"sharedWith,omitempty"` //An array of strings (Mainly Email Addresses)
	CloudDriveId				string			`json:"cloudDriveId,omitempty"`
	DetectionSourceAlias		string			`json:"detectionSourceAlias,omitempty"`
	FileId						string			`json:"fileId,omitempty"`
	Exposure					[]string		`json:"exposure,omitempty"`
	ProcessOwner				string			`json:"processOwner,omitempty"`
	ProcessName					string			`json:"processName,omitempty"`
	RemovableMediaVendor		string			`json:"removableMediaVendor,omitempty"`
	RemovableMediaName			string			`json:"removableMediaName,omitempty"`
	RemovableMediaSerialNumber	string			`json:"removableMediaSerialNumber,omitempty"`
	RemovableMediaCapacity		int				`json:"removableMediaCapacity,omitempty"`
	RemovableMediaBusType		string			`json:"removableMediaBusType,omitempty"`
	SyncDestination				string			`json:"syncDestination,omitempty"`
}

//Structs of Crashplan FFS API Authentication Token Return
type AuthData struct {
	Data AuthToken `json:"data"`
}
type AuthToken struct {
	V3UserToken string `json:"v3_user_token"`
}

//TODO Determine if I want to provide the API URLs or if they should be provided as constants here.

func GetAuthData(uri string, username string, password string) (*AuthData,error) {
	//Build HTTP GET request
	req, err := http.NewRequest("GET", uri, nil)

	//Return nil and err if Building of HTTP GET request fails
	if err != nil {
		return nil,err
	}

	//Set Basic Auth Header
	req.SetBasicAuth(username, password)
	//Set Accept Header
	req.Header.Set("Accept","application/json")

	//Make the HTTP Call
	resp, err := http.DefaultClient.Do(req)

	//Return nil and err if Building of HTTP GET request fails
	if err != nil {
		return nil,err
	}

	defer resp.Body.Close()

	//Return err if status code != 200
	if resp.StatusCode != http.StatusOK {
		return nil,errors.New("Error with Authentication Token GET: " + resp.Status)
	}

	//Create AuthData variable
	var authData AuthData

	//Decode the resp.Body into authData variable
	err = json.NewDecoder(resp.Body).Decode(&authData)

	//Return nil and err if decoding of resp.Body fails
	if err != nil {
		return nil,err
	}

	//Return AuthData
	return &authData,nil
}