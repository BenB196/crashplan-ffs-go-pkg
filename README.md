# crashplan-ffs-go-module
A third-party Golang module for Code42's Crashplan Forensic File Search (FFS) API

The goal of this Golang module is to provide an easy to use/integrate module for Code42's Crashplan FFS API. There are two main functions that can be used within the module:

1. GetAuthData
2. GetFileEvents

These functions allow for someone to query the Crashplan FFS API and get the results returned in a Golang struct which can then be used for other purposes.

## GetAuthData function
The GetAuthData is intended to get an API token for a user that will last for one (1) hour, which can then be used with the GetFileEvents function.

Arguments:
- uri - This is the URL which will provide the API token. (I believe it will always be: https://www.crashplan.com/c42api/v3/auth/jwt?useBody=true)
- username -  The username of the account that has permissions to access the FFS API. (This must be an email address according to the API)
- password -  The password of the account that is set as the username.

Returns:
- AuthData - Golang struct that contains the API token.
```
#AuthData struct structure
AuthData
    Data            AuthToken

AuthToken
    V3UserToken     string
```
- error - Any errors.

## GetFileEvents function

The GetFileEvents is intended to gather all events for a passed query and return them as a Golang struct slice.

Arguments:
- authData -  This is the Golang struct which is gotten from the GetAuthData function.
- ffsURI - This is the URL which actually hosts the FFS API. (See Code42 documentation for URI, default is https://forensicsearch-default.prod.ffs.us2.code42.com/forensic-search/queryservice/api/v1/)
- jsonQuery - This is the properly formatted JSON Query string which is what is actually executed against the Code42 Crashplan FFS API. (See documentation for how to properly format these queries.)
  - Example JSON query (Returns all events within a 5 second delta)
```
{
    "groups":[
       {
          "filters":[
             {
                "operator":"IS",
                "term":"fileName",
                "value":"*"
             },
             {
                "operator":"ON_OR_AFTER",
                "term":"insertionTimestamp",
                "value":"2019-08-18T20:31:48.728Z"
             },
             {
                "operator":"ON_OR_BEFORE",
                "term":"insertionTimestamp",
                "value":"2019-08-18T20:32:03.728Z"
             }
          ],
          "filterClause":"AND"
       }
    ],
    "groupClause":"AND",
    "pgNum":1,
    "pgSize":100,
    "srtDir":"asc",
    "srtKey":"insertionTimestamp"
}
  ```
Returns:

- []FileEvent - Golang struct slice that contains all events returned from the jsonQuery string

```
#FileEvent struct structure
FileEvent
    EventId                     string	
    EventType                   string	
    EventTimestamp              time.Time
    InsertionTimestamp          time.Time
    FilePath                    string	
    FileName                    string	
    FileType                    string	
    FileCategory                string	
    FileSize                    int		
    FileOwner                   string	
    Md5Checksum                 string	
    Sha256Checksum              string	
    CreatedTimestamp            time.Time
    ModifyTimestamp             time.Time
    DeviceUserName              string	
    DeviceUid                   string	
    UserUid                     string	
    OsHostName                  string	
    DomainName                  string	
    PublicIpAddress             string	
    PrivateIpAddresses          []string
    Actor                       string	
    DirectoryId                 []string
    Source                      string	
    Url                         string	
    Shared                      string	
    SharedWith                  []string
    SharingTypeAdded            []string
    CloudDriveId                string	
    DetectionSourceAlias        string	
    FileId                      string	
    Exposure                    []string
    ProcessOwner                string	
    ProcessName                 string	
    RemovableMediaVendor        string	
    RemovableMediaName          string	
    RemovableMediaSerialNumber  string	
    RemovableMediaCapacity      int		
    RemovableMediaBusType       string	
    SyncDestination             string	
```

- error - Any errors.

Limitations:

Code42 Crashplan FFS API has limitations like most APIs, these limitations affect the GetFileEvents function:

1. 120 Queries per minute, any additional queries will be dropped. (never actually bothered to test if this limit is actually enforced)
2. 200,000 results returned per query. This limitation is kind of annoying to handle as there is no easy way to handle it. The API does not support paging and the only way to figure out how many results there is for a query is to first query, count, then if over 200,000 results, break up the query into smaller time increments and perform multiple queries  to get all of the results.

## Code42 Documentation

Links for Code42 Documentation

- [Crashplan FFS API Documentation](https://support.code42.com/Administrator/Cloud/Monitoring_and_managing/Forensic_File_Search_API)

## TODOs

1. Figure out a way to build tests for these functions