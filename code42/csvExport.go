package code42

import (
	"encoding/csv"
	"encoding/hex"
	"errors"
	"github.com/spkg/bom"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FFS CSV Export

//The CSV main body of a file event record
type CsvFileEvent struct {
	EventId                     string     `json:"eventId,omitempty"`
	EventType                   string     `json:"eventType,omitempty"`
	EventTimestamp              *time.Time `json:"eventTimestamp,omitempty"`
	InsertionTimestamp          *time.Time `json:"insertionTimestamp,omitempty"`
	FilePath                    string     `json:"filePath,omitempty"`
	FileName                    string     `json:"fileName,omitempty"`
	FileType                    string     `json:"fileType,omitempty"`
	FileCategory                string     `json:"fileCategory,omitempty"`
	IdentifiedExtensionCategory string     `json:"identifiedExtensionCategory,omitempty"`
	CurrentExtensionCategory    string     `json:"currentExtensionCategory,omitempty"`
	FileSize                    *int       `json:"fileSize,omitempty"`
	FileOwner                   []string   `json:"fileOwner,omitempty"` //Array of owners
	Md5Checksum                 string     `json:"md5Checksum,omitempty"`
	Sha256Checksum              string     `json:"sha256Checksum,omitempty"`
	CreatedTimestamp            *time.Time `json:"createdTimestamp,omitempty"`
	ModifyTimestamp             *time.Time `json:"modifyTimestamp,omitempty"`
	DeviceUsername              string     `json:"deviceUsername,omitempty"`
	DeviceUid                   string     `json:"deviceUid,omitempty"`
	UserUid                     string     `json:"userUid,omitempty"`
	OsHostname                  string     `json:"osHostname,omitempty"`
	DomainName                  string     `json:"domainName,omitempty"`
	PublicIpAddress             string     `json:"publicIpAddress,omitempty"`
	PrivateIpAddresses          []string   `json:"privateIpAddresses,omitempty"` //Array of IP address strings
	Actor                       string     `json:"actor,omitempty"`
	DirectoryId                 []string   `json:"directoryId,omitempty"` //An array of something, I am not sure
	Source                      string     `json:"source,omitempty"`
	Url                         string     `json:"url,omitempty"`
	Shared                      *bool      `json:"shared,omitempty"`
	SharedWith                  []string   `json:"sharedWith,omitempty"` //An array of strings (Mainly Email Addresses)
	SharingTypeAdded            []string   `json:"sharingTypeAdded,omitempty"`
	CloudDriveId                string     `json:"cloudDriveId,omitempty"`
	DetectionSourceAlias        string     `json:"detectionSourceAlias,omitempty"`
	FileId                      string     `json:"fileId,omitempty"`
	Exposure                    []string   `json:"exposure,omitempty"`
	ProcessOwner                string     `json:"processOwner,omitempty"`
	ProcessName                 string     `json:"processName,omitempty"`
	TabWindowTitle              string     `json:"tabWindowTitle,omitempty"`
	TabUrl                      string     `json:"tabUrl,omitempty"`
	TabTitles                   []string   `json:"tabTitles,omitempty"`
	TabURLs                     []string   `json:"tabURLs,omitempty"`
	RemovableMediaVendor        string     `json:"removableMediaVendor,omitempty"`
	RemovableMediaName          string     `json:"removableMediaName,omitempty"`
	RemovableMediaSerialNumber  string     `json:"removableMediaSerialNumber,omitempty"`
	RemovableMediaCapacity      *int       `json:"removableMediaCapacity,omitempty"`
	RemovableMediaBusType       string     `json:"removableMediaBusType,omitempty"`
	RemovableMediaMediaName     string     `json:"removableMediaMediaName,omitempty"`
	RemovableMediaVolumeName    string     `json:"removableMediaVolumeName,omitempty"`
	RemovableMediaPartitionId   string     `json:"removableMediaPartitionId,omitempty"`
	SyncDestination             string     `json:"syncDestination,omitempty"`
	SyncDestinationUsername     string     `json:"syncDestinationUsername,omitempty"`
	EmailDLPPolicyNames         []string   `json:"emailDLPPolicyNames,omitempty"`
	EmailDLPSubject             string     `json:"emailDLPSubject,omitempty"`
	EmailDLPSender              string     `json:"emailDLPSender,omitempty"`
	EmailDLPFrom                string     `json:"emailDLPFrom,omitempty"`
	EmailDLPRecipients          []string   `json:"emailDLPRecipients,omitempty"`
	OutsideActiveHours          *bool      `json:"outsideActiveHours,omitempty"`
	IdentifiedExtensionMIMEType string     `json:"identifiedExtensionMimeType,omitempty"`
	CurrentExtensionMIMEType    string     `json:"currentExtensionMimeType,omitempty"`
	SuspiciousFileTypeMismatch  *bool      `json:"suspiciousFileTypeMismatch,omitempty"`
	PrintJobName                string     `json:"printJobName,omitempty"`
	PrinterName                 string     `json:"printerName,omitempty"`
	PrintedFilesBackupPath      string     `json:"printedFilesBackupPath,omitempty"`
	RemoteActivity              string     `json:"remoteActivity,omitempty"`
	Trusted                     *bool      `json:"trusted,omitempty"`
	LoggedInOperatingSystemUser string     `json:"loggedInOperatingSystemUser,omitempty"`
	DestinationCategory         string     `json:"destinationCategory,omitempty"`
	DestinationName             string     `json:"destinationName,omitempty"`
}

//Currently recognized csv headers
var csvHeaders = []string{"Event ID", "Event type", "Date Observed (UTC)", "Date Inserted (UTC)", "File path", "Filename", "File type", "File Category", "Identified Extension Category", "Current Extension Category", "File size (bytes)", "File Owner", "MD5 Hash", "SHA-256 Hash", "Create Date", "Modified Date", "Username", "Device ID", "User UID", "Hostname", "Fully Qualified Domain Name", "IP address (public)", "IP address (private)", "Actor", "Directory ID", "Source", "URL", "Shared", "Shared With Users", "File exposure changed to", "Cloud drive ID", "Detection Source Alias", "File Id", "Exposure Type", "Process Owner", "Process Name", "Tab/Window Title", "Tab URL", "Table Titles", "Tab URLs", "Removable Media Vendor", "Removable Media Name", "Removable Media Serial Number", "Removable Media Capacity", "Removable Media Bus Type", "Removable Media Media Name", "Removable Media Volume Name", "Removable Media Partition Id", "Sync Destination", "Sync Destination Username", "Email DLP Policy Names", "Email DLP Subject", "Email DLP Sender", "Email DLP From", "Email DLP Recipients", "Outside Active Hours", "Identified Extension MIME Type", "Current Extension MIME Type", "Suspicious File Type Mismatch", "Print Job Name", "Printer Name", "Printed Files Backup Path", "Remote Activity", "Trusted", "Logged in Operating System User", "Destination Category", "Destination Name"}

/*
csvLineToCsvFileEvent - Converts a CSV Line into a File Event Struct
[]string - csv line. DO NOT PASS Line 0 (Headers) if they exist
This function contains panics in order to prevent messed up CSV parsing
*/
func csvLineToCsvFileEvent(csvLine []string) *CsvFileEvent {
	//Init variables
	var fileEvent CsvFileEvent
	var err error

	//set eventId
	fileEvent.EventId = csvLine[0]

	//set eventType
	fileEvent.EventType = csvLine[1]

	//set eventTimestamp
	//Convert eventTimeStamp to time
	if csvLine[2] != "" {
		var eventTimeStamp time.Time
		eventTimeStamp, err = time.Parse(time.RFC3339Nano, csvLine[2])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing eventTimeStampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.EventTimestamp = &eventTimeStamp
	} else {
		fileEvent.EventTimestamp = nil
	}

	//set insertionTimestamp
	//Convert insertionTimestamp to time
	if csvLine[3] != "" {
		var insertionTimestamp time.Time
		insertionTimestamp, err = time.Parse(time.RFC3339Nano, csvLine[3])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing insertionTimestampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.InsertionTimestamp = &insertionTimestamp
	} else {
		fileEvent.InsertionTimestamp = nil
	}

	//set filePath
	fileEvent.FilePath = csvLine[4]

	//set fileName
	fileEvent.FileName = csvLine[5]

	//set fileType
	fileEvent.FileType = csvLine[6]

	//set fileCategory
	fileEvent.FileCategory = csvLine[7]

	//set identifiedExtensionCategory
	fileEvent.IdentifiedExtensionCategory = csvLine[8]

	//set currentExtensionCategory
	fileEvent.CurrentExtensionCategory = csvLine[9]

	//set fileSize
	//Convert fileSizeString to int
	if csvLine[10] != "" {
		var fileSize int
		fileSize, err = strconv.Atoi(csvLine[10])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing fileSizeString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.FileSize = &fileSize
	} else {
		fileEvent.FileSize = nil
	}

	//set fileOwner
	//Convert fileOwnerString to string slice

	if csvLine[11] != "" {
		fileEvent.FileOwner = strings.Split(csvLine[11], ",")
	} else {
		fileEvent.FileOwner = nil
	}

	//set md5Checksum
	fileEvent.Md5Checksum = csvLine[12]

	//set sha256Checksum
	fileEvent.Sha256Checksum = csvLine[13]

	//set createdTimestampString
	//Convert createdTimestamp to time
	if csvLine[14] != "" {
		var createdTimestamp time.Time
		createdTimestamp, err = time.Parse("2006-01-02 15:04:05", csvLine[14])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing createdTimestampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
		fileEvent.CreatedTimestamp = &createdTimestamp
	} else {
		fileEvent.CreatedTimestamp = nil
	}

	//set modifyTimestampString
	//Convert modifyTimestamp to time
	if csvLine[15] != "" {
		var modifyTimestamp time.Time
		modifyTimestamp, err = time.Parse("2006-01-02 15:04:05", csvLine[15])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing modifyTimestampString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
		fileEvent.ModifyTimestamp = &modifyTimestamp
	} else {
		fileEvent.ModifyTimestamp = nil
	}

	//set deviceUserName
	fileEvent.DeviceUsername = csvLine[16]

	//set deviceUid
	fileEvent.DeviceUid = csvLine[17]

	//set userUid
	fileEvent.UserUid = csvLine[18]

	//set osHostName
	fileEvent.OsHostname = csvLine[19]

	//set domainName
	fileEvent.DomainName = csvLine[20]

	//set publicIpAddress
	if csvLine[21] != "" {
		fileEvent.PublicIpAddress = strings.Replace(strings.Replace(csvLine[21], "/", "", -1), ":0", "", -1)
	}

	//set privateIpAddresses
	//Convert privateIpAddresses to string slice
	if csvLine[22] != "" {
		fileEvent.PrivateIpAddresses = strings.Split(csvLine[22], ",")
	} else {
		fileEvent.PrivateIpAddresses = nil
	}

	//set actor
	fileEvent.Actor = csvLine[23]

	//set directoryId
	//Convert directoryId to string slice
	if csvLine[24] != "" {
		fileEvent.DirectoryId = strings.Split(csvLine[24], ",")
	} else {
		fileEvent.DirectoryId = nil
	}

	//set source
	fileEvent.Source = csvLine[25]

	//set url
	fileEvent.Url = csvLine[26]

	//set shared
	//Convert shared to bool

	if csvLine[27] != "" {
		var shared bool
		shared, err = strconv.ParseBool(csvLine[27])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing shared, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}
		fileEvent.Shared = &shared
	} else {
		fileEvent.Shared = nil
	}

	//set sharedWith
	//Convert sharedWith to string slice
	if csvLine[28] != "" {
		fileEvent.SharedWith = strings.Split(csvLine[28], ",")
	} else {
		fileEvent.SharedWith = nil
	}

	//set sharingTypeAdded
	//Convert sharingTypeAdded to string slice
	if csvLine[29] != "" {
		fileEvent.SharingTypeAdded = strings.Split(csvLine[29], ",")
	} else {
		fileEvent.SharingTypeAdded = nil
	}

	//set cloudDriveId
	fileEvent.CloudDriveId = csvLine[30]

	//set detectionSourceAlias
	fileEvent.DetectionSourceAlias = csvLine[31]

	//set fileId
	fileEvent.FileId = csvLine[32]

	//set exposure
	//Convert exposure to string slice
	if csvLine[33] != "" {
		fileEvent.Exposure = strings.Split(csvLine[33], ",")
	} else {
		fileEvent.Exposure = nil
	}

	//set processOwner
	fileEvent.ProcessOwner = csvLine[34]

	//set processName
	fileEvent.ProcessName = csvLine[35]

	//set tabWindowTitle
	fileEvent.TabWindowTitle = csvLine[36]

	//set tabUrl
	fileEvent.TabUrl = csvLine[37]

	//set tabTitles
	//Convert tabTitles to string slice
	if csvLine[38] != "" {
		fileEvent.Exposure = strings.Split(csvLine[38], ",")
	} else {
		fileEvent.Exposure = nil
	}

	//set tabURLs
	//Convert tabURLs to string slice
	if csvLine[39] != "" {
		fileEvent.Exposure = strings.Split(csvLine[39], ",")
	} else {
		fileEvent.Exposure = nil
	}

	//set removableMediaVendor
	fileEvent.RemovableMediaVendor = csvLine[40]

	//set removableMediaName
	fileEvent.RemovableMediaName = csvLine[41]

	//set removableMediaSerialNumber
	fileEvent.RemovableMediaSerialNumber = csvLine[42]

	//set removableMediaCapacity
	//Convert removableMediaCapacity to int
	if csvLine[43] != "" {
		var removableMediaCapacity int
		removableMediaCapacity, err = strconv.Atoi(csvLine[43])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing removableMediaCapacityString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.RemovableMediaCapacity = &removableMediaCapacity
	} else {
		fileEvent.RemovableMediaCapacity = nil
	}

	//set removableMediaBusType
	fileEvent.RemovableMediaBusType = csvLine[44]

	//set removableMediaMediaName
	fileEvent.RemovableMediaMediaName = csvLine[45]

	//set removableMediaVolumeName
	fileEvent.RemovableMediaVolumeName = csvLine[46]

	//set removableMediaPartitionId
	fileEvent.RemovableMediaPartitionId = csvLine[47]

	//set syncDestination
	fileEvent.SyncDestination = csvLine[48]

	//set syncDestinationUsername
	fileEvent.SyncDestinationUsername = csvLine[49]

	//set emailDLPPolicyNames
	//Convert emailDLPPolicyNames to string slice
	if csvLine[50] != "" {
		fileEvent.EmailDLPPolicyNames = strings.Split(csvLine[50], ",")
	} else {
		fileEvent.EmailDLPPolicyNames = nil
	}

	//set emailDLPSubject
	fileEvent.EmailDLPSubject = csvLine[51]

	//set emailDLPSender
	fileEvent.EmailDLPSender = csvLine[52]

	//set emailDLPFrom
	fileEvent.EmailDLPFrom = csvLine[53]

	//set emailDLPRecipients
	//Convert emailDLPRecipients to string slice
	if csvLine[54] != "" {
		fileEvent.EmailDLPRecipients = strings.Split(csvLine[54], ",")
	} else {
		fileEvent.EmailDLPRecipients = nil
	}

	//set outsideActiveHours
	if csvLine[55] != "" {
		var outsideActiveHours bool
		outsideActiveHours, err = strconv.ParseBool(csvLine[55])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing outsideActiveHoursString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.OutsideActiveHours = &outsideActiveHours
	} else {
		fileEvent.OutsideActiveHours = nil
	}

	//set identifiedExtensionMimeType
	fileEvent.IdentifiedExtensionMIMEType = csvLine[56]

	//set currentExtensionMimeType
	fileEvent.CurrentExtensionMIMEType = csvLine[57]

	//set suspiciousFileTypeMismatch
	if csvLine[58] != "" {
		var suspiciousFileTypeMismatch bool
		suspiciousFileTypeMismatch, err = strconv.ParseBool(csvLine[58])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing suspiciousFileTypeMismatchString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.SuspiciousFileTypeMismatch = &suspiciousFileTypeMismatch
	} else {
		fileEvent.SuspiciousFileTypeMismatch = nil
	}

	//set printJobName
	fileEvent.PrintJobName = csvLine[59]

	//set printerName
	fileEvent.PrinterName = csvLine[60]

	//set printedFilesBackupPath
	fileEvent.PrintedFilesBackupPath = csvLine[61]

	//set remoteActivity
	fileEvent.RemoteActivity = csvLine[62]

	//set trusted
	if csvLine[63] != "" {
		var trusted bool
		trusted, err = strconv.ParseBool(csvLine[63])

		//Panic if this fails, that means something is wrong with CSV handling
		if err != nil {
			log.Println("Error parsing trustedString, something must be wrong with CSV parsing.")
			log.Println(csvLine)
			panic(err)
		}

		fileEvent.Trusted = &trusted
	} else {
		fileEvent.Trusted = nil
	}

	//set loggedInOperatingSystemUser
	fileEvent.LoggedInOperatingSystemUser = csvLine[64]

	//set destinationCategory
	fileEvent.DestinationCategory = csvLine[65]

	//set destinationName
	fileEvent.DestinationName = csvLine[66]

	return &fileEvent
}

/*
getCsvFileEvents - Function to get the actual event records from FFS
*http.Response from ExecQuery
This function contains a panic if the csv columns do not match the currently specified list.
This is to prevent data from being messed up during parsing.
*/
func GetCsvFileEvents(resp *http.Response) (*[]CsvFileEvent, error) {
	//Read Response Body as CSV
	//reader := csv.NewReader(resp.Body)
	reader := csv.NewReader(bom.NewReader(resp.Body))
	reader.Comma = ','

	//Read body into variable
	data, err := reader.ReadAll()

	//Handle reader errors
	if err != nil {
		return nil, err
	}

	var fileEvents []CsvFileEvent

	//Loop through CSV lines
	var wg sync.WaitGroup
	wg.Add(len(data))
	go func() {
		for lineNumber, lineContent := range data {
			if lineNumber != 0 {
				//Convert CSV line to file events and add to slice
				fileEvents = append(fileEvents, *csvLineToCsvFileEvent(lineContent))
			} else {
				//Validate that the columns have not changed
				err = equal(lineContent, csvHeaders)

				if err != nil {
					println(err.Error())
					panic(errors.New("number of columns in CSV file does not match expected number, API changed, panicking to keep data integrity. New CSV columns: " + strings.Join(lineContent, ",")))
				}
			}
			wg.Done()
		}
	}()

	wg.Wait()

	return &fileEvents, nil
}

/*
Calculate the difference between two different slices
Used in this case to tell if the csv columns have changed
*/
func equal(slice1 []string, slice2 []string) error {
	if len(slice1) != len(slice2) {
		return errors.New("slices and CSV header sizes do not match, expected: " + strconv.Itoa(len(slice2)) + ", but got: " + strconv.Itoa(len(slice1)))
	}

	//loop through slices to check values
	for i, v := range slice1 {
		if i == len(slice1) - 1 {
			//if last element in slice1, remove potential eol char
			v = strings.Replace(v, "\r\n", "", -1)
			v = strings.Replace(v, "\r", "", -1)
			v = strings.Replace(v, "\n", "", -1)

			//we don't need to worry about slice2, its static
			if v != slice2[i] {
				println("error with last element in csv headers")
				println("slice1[i] bytes:")
				println([]byte(v))
				println("slice1[i] hex:")
				println(hex.EncodeToString([]byte(v)))
				println("slice2[i] bytes:")
				println([]byte(slice2[i]))
				println("slice2[i] hex:")
				println(hex.EncodeToString([]byte(slice2[i])))
				return errors.New("column order/naming does not match; slice1: i = " + strconv.Itoa(i) + ", v = " + v + "; slice2 v = " + slice2[i])
			}
		} else {
			if v != slice2[i] {
				println("slice1[i] bytes:")
				println([]byte(v))
				println("slice1[i] hex:")
				println(hex.EncodeToString([]byte(v)))
				println("slice2[i] bytes:")
				println([]byte(slice2[i]))
				println("slice2[i] hex:")
				println(hex.EncodeToString([]byte(slice2[i])))
				return errors.New("column order/naming does not match; slice1: i = " + strconv.Itoa(i) + ", v = " + v + "; slice2 v = " + slice2[i])
			}
		}
	}

	return nil
}