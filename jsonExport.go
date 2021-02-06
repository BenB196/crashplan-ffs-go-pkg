package ffs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

type JsonFileEvent struct {
	Actor                      string       `json:"actor,omitempty"`
	CloudDriveId               string       `json:"cloudDriveId,omitempty"`
	CreateTimestamp            string       `json:"createTimestamp,omitempty"`
	DestinationCategory        string       `json:"destinationCategory,omitempty"`
	DestinationName            string       `json:"destinationName,omitempty"`
	DetectionSourceAlias       string       `json:"detectionSourceAlias,omitempty"`
	DeviceUid                  string       `json:"deviceUid,omitempty"`
	DeviceUserName             string       `json:"deviceUserName,omitempty"`
	DirectoryId                []string     `json:"directoryId,omitempty"`
	DomainName                 string       `json:"domainName,omitempty"`
	EmailDlpPolicyNames        []string     `json:"emailDlpPolicyNames,omitempty"`
	EmailFrom                  string       `json:"emailFrom,omitempty"`
	EmailRecipients            []string     `json:"emailRecipients,omitempty"`
	EmailSender                string       `json:"emailSender,omitempty"`
	EmailSubject               string       `json:"emailSubject,omitempty"`
	EventId                    string       `json:"eventId"`
	EventTimestamp             string       `json:"eventTimestamp,omitempty"`
	EventType                  string       `json:"eventType,omitempty"`
	Exposure                   []string     `json:"exposure,omitempty"`
	FieldErrors                []FieldError `json:"fieldErrors,omitempty"`
	FileCategory               string       `json:"fileCategory,omitempty"`
	FileCategoryByBytes        string       `json:"fileCategoryByBytes,omitempty"`
	FileCategoryByExtension    string       `json:"fileCategoryByExtension,omitempty"`
	FileId                     string       `json:"fileId,omitempty"`
	FileName                   string       `json:"fileName,omitempty"`
	FileOwner                  string       `json:"fileOwner,omitempty"`
	FilePath                   string       `json:"filePath,omitempty"`
	FileSize                   *int64       `json:"fileSize,omitempty"`
	FileType                   string       `json:"fileType,omitempty"`
	InsertionTimestamp         string       `json:"insertionTimestamp,omitempty"`
	Md5Checksum                string       `json:"md5Checksum,omitempty"`
	MimeTypeByBytes            string       `json:"mimeTypeByBytes,omitempty"`
	MimeTypeByExtension        string       `json:"mimeTypeByExtension,omitempty"`
	MimeTypeMismatch           *bool        `json:"mimeTypeMismatch,omitempty"`
	ModifyTimestamp            string       `json:"modifyTimestamp,omitempty"`
	OperatingSystemUser        string       `json:"operatingSystemUser,omitempty"`
	OsHostName                 string       `json:"osHostName,omitempty"`
	OutsideActiveHours         *bool        `json:"outsideActiveHours,omitempty"`
	PrintJobName               string       `json:"printJobName,omitempty"`
	PrinterName                string       `json:"printerName,omitempty"`
	PrivateIpAddresses         []string     `json:"privateIpAddresses,omitempty"`
	ProcessName                string       `json:"processName,omitempty"`
	ProcessOwner               string       `json:"processOwner,omitempty"`
	PublicIpAddress            string       `json:"publicIpAddress,omitempty"`
	RemoteActivity             string       `json:"remoteActivity,omitempty"`
	RemovableMediaBusType      string       `json:"removableMediaBusType,omitempty"`
	RemovableMediaCapacity     *int64       `json:"removableMediaCapacity,omitempty"`
	RemovableMediaMediaName    string       `json:"removableMediaMediaName,omitempty"`
	RemovableMediaName         string       `json:"removableMediaName,omitempty"`
	RemovableMediaPartitionId  []string     `json:"removableMediaPartitionId,omitempty"`
	RemovableMediaSerialNumber string       `json:"removableMediaSerialNumber,omitempty"`
	RemovableMediaVendor       string       `json:"removableMediaVendor,omitempty"`
	RemovableMediaVolumeName   []string     `json:"removableMediaVolumeName,omitempty"`
	Sha256Checksum             string       `json:"sha256Checksum,omitempty"`
	Shared                     string       `json:"shared,omitempty"`
	SharedWith                 []SharedWith `json:"sharedWith,omitempty"`
	SharingTypeAdded           []string     `json:"sharingTypeAdded,omitempty"`
	Source                     string       `json:"source,omitempty"`
	SyncDestination            string       `json:"syncDestination,omitempty"`
	SyncDestinationUsername    []string     `json:"syncDestinationUsername,omitempty"`
	TabUrl                     string       `json:"tabUrl,omitempty"`
	Tabs                       []Tab        `json:"tabs,omitempty"`
	Trusted                    *bool        `json:"trusted,omitempty"`
	Url                        string       `json:"url,omitempty"`
	UserUid                    string       `json:"userUid,omitempty"`
	WindowTitle                []string     `json:"windowTitle,omitempty"`
}

type FieldError struct {
	Error string `json:"error,omitempty"`
	Field string `json:"field,omitempty"`
}

type SharedWith struct {
	CloudUsername *string `json:"cloudUsername,omitempty"`
}

type Tab struct {
	Title string `json:"title,omitempty"`
	Url   string `json:"url,omitempty"`
}

type JsonFileEventResponse struct {
	FileEvents  []JsonFileEvent `json:"fileEvents,omitempty"`
	NextPgToken string          `json:"nextPgToken,omitempty"`
	Problems    []QueryProblem  `json:"problems,omitempty"`
	TotalCount  *int64          `json:"totalCount,omitempty"`
}

func GetJsonFileEventResponse(resp *http.Response) (*JsonFileEventResponse, error) {
	var eventResponse JsonFileEventResponse

	//Read Response Body as JSON
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &eventResponse)

	if err != nil {
		return nil, err
	}

	return &eventResponse, nil
}

func GetJsonFileEvents(authData AuthData, ffsURI string, query Query, pgToken string) (*[]JsonFileEvent, string, error) {
	var jsonFileEvents []JsonFileEvent

	if pgToken != "" {
		query.PgToken = pgToken
	}

	//Validate jsonQuery is valid JSON
	ffsQuery, err := json.Marshal(query)
	if err != nil {
		return nil, "", errors.New("jsonQuery is not in a valid json format")
	}

	//Make sure authData token is not ""
	if authData.Data.V3UserToken == "" {
		return nil, "", errors.New("authData cannot be nil")
	}

	//Query ffsURI with authData API token and jsonQuery body
	req, err := http.NewRequest("POST", ffsURI, bytes.NewReader(ffsQuery))

	//Handle request errors
	if err != nil {
		return nil, "", err
	}

	//Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "v3_user_token "+authData.Data.V3UserToken)

	//Get Response
	resp, err := http.DefaultClient.Do(req)

	//Handle response errors
	if err != nil {
		return nil, "", err
	}

	//defer body close
	defer resp.Body.Close()

	//Make sure http status code is 200
	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.New("Error with gathering file events POST: " + resp.Status)
	}

	fileEventResponse, err := GetJsonFileEventResponse(resp)

	if err != nil {
		return nil, "", err
	}

	if fileEventResponse.Problems != nil {
		problems, err := json.Marshal(fileEventResponse.Problems)

		if err != nil {
			return nil, "", err
		}

		return nil, "", errors.New(string(problems))
	}

	if len(fileEventResponse.FileEvents) == 0 {
		fileEventResponse.FileEvents = nil
	} else {
		jsonFileEvents = append(jsonFileEvents, fileEventResponse.FileEvents...)
	}

	var nextJsonFileEvents *[]JsonFileEvent

	if fileEventResponse.NextPgToken != "" {
		log.Print("Next Page Token: ")
		log.Println(fileEventResponse.NextPgToken)

		nextJsonFileEvents, _, err = GetJsonFileEvents(authData, ffsURI, query, fileEventResponse.NextPgToken)

		if err != nil {
			return nil, "", err
		}

		if nextJsonFileEvents != nil && len(*nextJsonFileEvents) != 0 {
			jsonFileEvents = append(jsonFileEvents, *nextJsonFileEvents...)
		}
	}

	return &jsonFileEvents, "", nil
}
