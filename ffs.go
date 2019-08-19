//Packages provide a module for using the Code42 Crashplan FFS API
package ffs

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//The main body of a file event record
type FileEvent struct {
	EventId						string			`json:"eventId"`
	EventType					string			`json:"eventType"`
	EventTimestamp				time.Time		`json:"eventTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	InsertionTimestamp			time.Time		`json:"insertionTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	FilePath					string			`json:"filePath"`
	FileName					string			`json:"fileName"`
	FileType					string			`json:"fileType"`
	FileCategory				string			`json:"fileCategory"`
	FileSize					int				`json:"fileSize"`
	FileOwner					string			`json:"fileOwner,omitempty"`
	Md5Checksum					string			`json:"md5Checksum,omitempty"`
	Sha256Checksum				string			`json:"sha256Checksum,omitempty"`
	CreatedTimestamp			time.Time		`json:"createdTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	ModifyTimestamp				time.Time		`json:"modifyTimestamp,omitempty"` //This is really a time (might be better to convert to a time instead of a string)
	DeviceUserName				string			`json:"deviceUserName"`
	DeviceUid					string			`json:"deviceUid"`
	UserUid						string			`json:"userUid"`
	OsHostName					string			`json:"osHostName"`
	DomainName					string			`json:"domainName"`
	PublicIpAddress				string			`json:"publicIpAddress,omitempty"`
	PrivateIpAddresses			[]string		`json:"privateIpAddresses"` //Array of IP address strings
	Actor						string			`json:"actor,omitempty"`
	DirectoryId					[]string		`json:"directoryId,omitempty"` //An array of something, I am not sure
	Source						string			`json:"source"`
	Url							string			`json:"url,omitempty"`
	Shared						string			`json:"shared,omitempty"`
	SharedWith					[]string		`json:"sharedWith,omitempty"` //An array of strings (Mainly Email Addresses)
	SharingTypeAdded			[]string		`json:"sharingTypeAdded,omitempty"`
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

/*
GetAuthData - Function to get the Authentication data (mainly the authentication token) which will be needed for the rest of the API calls
The authentication token is good for up to 1 hour before it expires
 */
func GetAuthData(uri string, username string, password string) (*AuthData,error) {
	//Build HTTP GET request
	req, err := http.NewRequest("GET", uri, nil)

	//Return nil and err if Building of HTTP GET request fails
	if err != nil {
		return nil, err
	}

	//Set Basic Auth Header
	req.SetBasicAuth(username, password)
	//Set Accept Header
	req.Header.Set("Accept","application/json")

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

	//Decode the resp.Body into authData variable
	err = json.NewDecoder(resp.Body).Decode(&authData)

	//Return nil and err if decoding of resp.Body fails
	if err != nil {
		return nil, err
	}

	//Return AuthData
	return &authData, nil
}

//TODO create Global Function for calling getFileEvents with CSV url formatting (Priority, as will likely continue to be supported by Code42)
/*
csvLineToFileEvent - Converts a CSV Line into a File Event Struct
[]string - csv line. DO NOT PASS Line 0 (Headers) if they exist
This function contains panics in order to prevent messed up CSV parsing
 */
func csvLineToFileEvent(csvLine []string) FileEvent {
	//Convert []string to designated variables
	eventId := csvLine[0]
	eventType := csvLine[1]
	eventTimestampString := csvLine[2] //Converted to time below
	insertionTimestampString := csvLine[3] //Converted to time below
	filePath := csvLine[4]
	fileName := csvLine[5]
	fileType := csvLine[6]
	fileCategory := csvLine[7]
	fileSizeString := csvLine[8] //Converted to int below
	fileOwner := csvLine[9]
	md5Checksum := csvLine[10]
	sha256Checksum := csvLine[11]
	createdTimestampString := csvLine[12] //Converted to time below
	modifyTimestampString := csvLine[13] //Converted to time below
	deviceUserName := csvLine[14]
	deviceUid := csvLine[15]
	userUid := csvLine[16]
	osHostName := csvLine[17]
	domainName := csvLine[18]
	publicIpAddress := csvLine[19]
	privateIpAddressesString := csvLine[20] //Converted to slice below
	actor := csvLine[21]
	directoryIdString := csvLine[22] //Converted to slice below
	source := csvLine[23]
	url := csvLine[24]
	shared := csvLine[25]
	sharedWithString := csvLine[26] //Converted to slice below
	sharingTypeAddedString := csvLine[27] //Converted to slice below
	cloudDriveId := csvLine[28]
	detectionSourceAlias := csvLine[29]
	fileId := csvLine[30]
	exposureString := csvLine[31] //Convert to slice below
	processOwner := csvLine[32]
	processName := csvLine[33]
	removableMediaVendor := csvLine[34]
	removableMediaName := csvLine[35]
	removableMediaSerialNumber := csvLine[36]
	removableMediaCapacityString := csvLine[37] //Converted to int below
	removableMediaBusType := csvLine[38]
	syncDestination := csvLine[39]


	//Set err
	var err error

	//Convert eventTimeStamp to time
	var eventTimeStamp time.Time
	if eventTimestampString != "" {
		eventTimeStamp, err = time.Parse(time.RFC3339Nano, eventTimestampString)

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing eventTimeStampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
	}

	//Convert insertionTimestamp to time
	var insertionTimestamp time.Time
	if insertionTimestampString != "" {
		insertionTimestamp, err = time.Parse(time.RFC3339Nano, insertionTimestampString)

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing insertionTimestampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
	}

	//Convert fileSizeString to int
	var fileSize int
	if fileSizeString != "" {
		fileSize, err = strconv.Atoi(fileSizeString)

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing fileSizeString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
	}

	//Convert createdTimestamp to time
	var createdTimestamp time.Time
	if createdTimestampString != "" {
		createdTimestamp, err = time.Parse(time.RFC3339Nano, createdTimestampString)

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing createdTimestampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
	}

	//Convert modifyTimestamp to time
	var modifyTimestamp time.Time
	if modifyTimestampString != "" {
		modifyTimestamp, err = time.Parse(time.RFC3339Nano, modifyTimestampString)

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing modifyTimestampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
	}

	//Convert privateIpAddresses to string slice
	var privateIpAddresses []string
	if privateIpAddressesString != "" {
		privateIpAddressesString := strings.Replace(privateIpAddressesString, "\n","",-1)
		privateIpAddresses = strings.Fields(privateIpAddressesString)
	}

	//Convert directoryId to string slice
	var directoryId []string
	if directoryIdString != "" {
		directoryIdString := strings.Replace(directoryIdString, "\n","",-1)
		directoryId = strings.Fields(directoryIdString)
	}

	//Convert sharedWith to string slice
	var sharedWith []string
	if sharedWithString != "" {
		sharedWithString := strings.Replace(sharedWithString, "\n","",-1)
		sharedWith = strings.Fields(sharedWithString)
	}

	//Convert sharingTypeAdded to string slice
	var sharingTypeAdded []string
	if sharingTypeAddedString != "" {
		sharingTypeAddedString := strings.Replace(sharingTypeAddedString, "\n","",-1)
		sharingTypeAdded = strings.Fields(sharingTypeAddedString)
	}

	//Convert exposure to string slice
	var exposure []string
	if exposureString != "" {
		exposureString := strings.Replace(exposureString, "\n","",-1)
		exposure = strings.Fields(exposureString)
	}

	//Convert removableMediaCapacity to int
	var removableMediaCapacity int
	if removableMediaCapacityString != "" {
		removableMediaCapacity, err = strconv.Atoi(removableMediaCapacityString)

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing removableMediaCapacityString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
	}

	var fileEvent FileEvent

	fileEvent = FileEvent{
		EventId:                    eventId,
		EventType:                  eventType,
		EventTimestamp:             eventTimeStamp,
		InsertionTimestamp:         insertionTimestamp,
		FilePath:                   filePath,
		FileName:                   fileName,
		FileType:                   fileType,
		FileCategory:               fileCategory,
		FileSize:                   fileSize,
		FileOwner:                  fileOwner,
		Md5Checksum:                md5Checksum,
		Sha256Checksum:             sha256Checksum,
		CreatedTimestamp:           createdTimestamp,
		ModifyTimestamp:            modifyTimestamp,
		DeviceUserName:             deviceUserName,
		DeviceUid:                  deviceUid,
		UserUid:                    userUid,
		OsHostName:                 osHostName,
		DomainName:                 domainName,
		PublicIpAddress:            publicIpAddress,
		PrivateIpAddresses:         privateIpAddresses,
		Actor:                      actor,
		DirectoryId:                directoryId,
		Source:                     source,
		Url:                        url,
		Shared:                     shared,
		SharedWith:                 sharedWith,
		SharingTypeAdded:           sharingTypeAdded,
		CloudDriveId:               cloudDriveId,
		DetectionSourceAlias:       detectionSourceAlias,
		FileId:                     fileId,
		Exposure:                   exposure,
		ProcessOwner:               processOwner,
		ProcessName:                processName,
		RemovableMediaVendor:       removableMediaVendor,
		RemovableMediaName:         removableMediaName,
		RemovableMediaSerialNumber: removableMediaSerialNumber,
		RemovableMediaCapacity:     removableMediaCapacity,
		RemovableMediaBusType:      removableMediaBusType,
		SyncDestination:            syncDestination,
	}

	return fileEvent
}

//TODO create Global Function for calling getFileEvents with JSON url formatting (this may be deprecated by Code42 soon)

/*
getFileEvents - Function to get the actual event records from FFS
 */

//TODO Investigate Below
/*
How to handle the wide variety of query customizability (if it should be handled at all)
 */
func GetFileEvents(authData AuthData, ffsURI string, jsonQuery string) (*[]FileEvent,error) {

	//Validate jsonQuery is valid JSON
	var js map[string]interface{}
	if jsonQuery == "" {
		return nil, errors.New("jsonQuery cannot be empty")
	} else if !(json.Unmarshal([]byte(jsonQuery), &js) == nil) {
		return nil, errors.New("jsonQuery is not in a valid json format")
	}

	//Make sure authData token is not ""
	if authData.Data.V3UserToken == "" {
		return nil, errors.New("authData cannot be nil")
	}

	//Query ffsURI with authData API token and jsonQuery body
	req, err := http.NewRequest("POST", ffsURI, bytes.NewReader([]byte(jsonQuery)))

	//Handle request errors
	if err != nil {
		return nil, err
	}

	//Set request headers
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("Authorization","v3_user_token " + authData.Data.V3UserToken)

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

	//Read Response Body as CSV
	reader := csv.NewReader(resp.Body)
	reader.Comma = ','

	//Read body into variable
	data, err := reader.ReadAll()

	//Handle reader errors
	if err != nil {
		return nil, err
	}

	var fileEvents []FileEvent

	//Loop through CSV lines
	for lineNumber, lineContent := range data {
		if lineNumber != 0 {
			//Convert CSV line to file events and add to slice
			fileEvents = append(fileEvents, csvLineToFileEvent(lineContent))
		} else {
			//Validate that the correct number of columns is in the header line, if not panic, they changed the API
			//Current known number of columns
			numberOfColumns := 40
			if len(lineContent) != numberOfColumns {
				panic(errors.New("number of columns in CSV file does not match expected number, API changed, panicking to keep data integrity"))
			}
		}
	}

	return &fileEvents,nil
}