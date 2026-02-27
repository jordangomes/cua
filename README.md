# Current User Agent (CUA)

CUA is a small windows service i designed to log the current user on a device over time. It works by monitoring for interactive logon/logoff events and recording them. Each time one of these events is fired CUA checks the active console session to see if a user is logged in and grab their details.   

## Event Types

### logon_logoff_event
This is fired on windows Event ID 4624 (Logon) where the logon type is 2,7,10,11 and also Event ID 4647 (LogoffInteractive). 
These events are filtered to remove instances of [DWM](https://learn.microsoft.com/en-us/windows/win32/dwm/dwm-overview) and [UDMF](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/overview-of-the-umdf) as well as debounced by 100ms to prevent noisey logs.

Sample
```json
{
    "timestamp":"2026-02-27T05:22:35.461007Z",
    "level":"INFO",
    "action":"logon_logoff_event",
    "event_type":"LogoffInteractive",
    "user_sid":"S-1-12-1-2991438786-1147252871-734652841-3570430303",
    "username":"JordanGomes",
    "target":"cua"
}
```

### tenant_info
This is run after each logon/logoff event (probably excessive) and returns the below data on the tenant the device is a part of.  

Sample
```json
{
    "timestamp":"2026-02-27T05:23:28.361751Z",
    "level":"INFO",
    "action":"tenant_info",
    "tenant_id":"338f14b1-cb11-41e8-90ae-b06bc0fdd75a",
    "device_id":"af4edcd4-4bb6-4679-8b0e-64c3262a1de4",
    "registered_user":"test@jordangomes.com",
    "target":"cua::windows_api"
}
```

### current_user_info
This is run after each logon/logoff event and returns the below data on the user that is currently logged into the device.  

Sample for Azure User
```json
{
    "timestamp":"2026-02-27T05:23:28.362490Z",
    "level":"INFO",
    "action":"current_user_info",
    "user_sid":"S-1-12-1-2991438786-1147252871-734652841-3570430303",
    "username":"test@jordangomes.com",
    "user_type":"AzureAD",
    "azure_ad_object_id":"b24dbbc2-b087-4461-a9e9-c92b5f71d0d4",
    "target":"cua::windows_api"
}

```
Sample for Local User
```json
{
    "timestamp":"2026-02-27T05:22:56.570435Z",
    "level":"INFO",
    "action":"current_user_info",
    "user_sid":"S-1-5-21-406160441-2633804267-1261186540-1001",
    "username":"jordans-desktop\\Jordan",
    "user_type":"DomainOrLocal",
    "target":"cua::windows_api"
}
```