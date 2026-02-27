use std::ffi::{OsString};
use std::os::windows::ffi::OsStringExt;
use std::slice::{self, from_raw_parts};
use tracing::{debug};
use uuid::Uuid;

use windows::core::{PCWSTR, PWSTR, PSTR};
use windows::Win32::Foundation::{HANDLE, CloseHandle, HLOCAL, LocalFree, GetLastError};
use windows::Win32::Security::PSID;
use windows::Win32::Globalization::lstrlenW;
use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf, GetTokenInformation, TokenUser, TOKEN_USER};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Authentication::Identity::{GetUserNameExW, NameUserPrincipal, NameSamCompatible};
use windows::Win32::System::RemoteDesktop::{WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTSConnectState, WTSActive, WTSDisconnected, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationA, WTSQueryUserToken};

struct LocalHeapString {
    inner: PWSTR,
}

impl LocalHeapString {
    fn as_mut_ptr(&mut self) -> &mut PWSTR {
        &mut self.inner
    }
}

impl Default for LocalHeapString {
    fn default() -> Self {
        Self {
            inner: PWSTR::null(),
        }
    }
}

impl Drop for LocalHeapString {
    fn drop(&mut self) {
        if self.inner != PWSTR::null() {
            let free_me: HLOCAL = HLOCAL(self.inner.0 as *mut core::ffi::c_void);
            self.inner = PWSTR::null();
            let _ = unsafe { LocalFree(Some(free_me)) };
        }
    }
}

impl From<LocalHeapString> for String {
    fn from(value: LocalHeapString) -> Self {
        let as_constant_wide_string: PCWSTR = PCWSTR(value.inner.0);
        let s = unsafe { lstrlenW(as_constant_wide_string) };
        let v = unsafe { from_raw_parts(as_constant_wide_string.0, s as usize) };
        let as_os_string = OsString::from_wide(v);
        let as_rust_string = as_os_string.to_string_lossy();
        as_rust_string.into_owned()
    }
}

fn convert_sid_to_string(value: PSID) -> Result<String, std::io::Error> {
    let mut lhs = LocalHeapString::default();
    if unsafe { ConvertSidToStringSidW(value, lhs.as_mut_ptr()) }.is_err() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(lhs.into())
}

fn get_user_sid_from_token(token: HANDLE) -> Result<String, std::io::Error> {
    let mut return_length = 0;
    let mut buffer = vec![0u8; 1024]; // Buffer to hold the TOKEN_USER data

    let rv = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void), // Wrap in Some
            buffer.len() as u32,
            &mut return_length,
        )
    };

    if rv.is_err() {
        return Err(std::io::Error::last_os_error());
    }

    // The buffer now contains a TOKEN_USER structure
    let token_user = unsafe {
        // We're assuming the buffer contains the TOKEN_USER structure
        &*(buffer.as_ptr() as *const TOKEN_USER)
    };

    // Extract the PSID from the TOKEN_USER structure
    let user_sid = token_user.User.Sid;

    // Convert the SID to a string representation
    convert_sid_to_string(user_sid)
}

fn convert_azure_ad_sid_to_object_id(sid: &str) -> Option<String> {
    let sid = sid.replace("S-1-12-1-", "");

    let parts: Vec<u32> = sid.split('-')
        .filter_map(|part| part.parse::<u32>().ok())
        .collect();

    if parts.len() < 4 {
        return None;
    }

    let mut bytes = Vec::with_capacity(16);
    for &part in &parts[0..4] {
        bytes.extend_from_slice(&part.to_le_bytes());
    }

    while bytes.len() < 16 {
        bytes.push(0);
    }

    Uuid::from_slice(&bytes).ok().map(|uuid| uuid.to_string())
}

pub struct CurrentUserInfo {
    pub sid: String,
    pub username: String,
    pub user_type: String, // Added field for user type
    pub azure_ad_object_id: Option<String>, // Added optional field for Azure AD Object ID
}

pub fn get_user_info() -> Result<Option<CurrentUserInfo>, Box<dyn std::error::Error>> {
    // Check if there is an active console session
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFFFFFF {
        return Ok(None);
    }

    let mut buffer: PSTR = PSTR::null();
    let mut bytes_returned: u32 = 0;
    match unsafe { WTSQuerySessionInformationA(Some(WTS_CURRENT_SERVER_HANDLE), session_id, WTSConnectState, &mut buffer, &mut bytes_returned) } {
        Ok(_) => {
            if !buffer.is_null() && bytes_returned as usize >= std::mem::size_of::<WTS_CONNECTSTATE_CLASS>() {
                let state = unsafe{ *(buffer.0 as *const WTS_CONNECTSTATE_CLASS) };
                match state {
                    WTSActive => {debug!("Session Information for session id {} - WTSActive", session_id);},
                    WTSDisconnected => {debug!("Session Information for session id {} - WTSDisconnected", session_id);}
                    _ => {
                        debug!("Session Information for session id {} - {:?}", session_id, state);
                        return Ok(None);
                    }
                };
            } else {
                return Err(format!("Unable to get Session Information for session_id {} - invalid result buffer size", session_id).into())
            }
        },
        Err(e) => return Err(format!("Unable to get TSession Information for session_id {} - {}", session_id, e.message()).into())
    };

    // Query the active console session for a user token
    let mut h_token: HANDLE = HANDLE::default();
    match unsafe { WTSQueryUserToken(session_id, &mut h_token) } {
        Ok(_) => {},
        Err(e) => return Err(format!("Unable to get Token ID for session_id {} - {}", session_id, e.message()).into())
    };


    // Query the logged in users SID using the token 
    let user_sid = get_user_sid_from_token(h_token)?;

    // Determine the user type (Azure AD, or Domain/Local) based on SID
    let user_type = if user_sid.starts_with("S-1-12-1") {
        "AzureAD".to_string()
    } else {
        "DomainOrLocal".to_string()
    };


    match unsafe { ImpersonateLoggedOnUser(h_token) } {
        Ok(_) => {},
        Err(e) => return Err(e.message().into())
    };

    let mut buff_len = 1024;
    let mut username_buffer = Vec::<u16>::with_capacity(buff_len as usize);
    let lp_username_buffer = PWSTR(username_buffer.as_mut_ptr());
    let result = match user_type.as_str() {
        "AzureAD" => unsafe { GetUserNameExW(NameUserPrincipal,Some(lp_username_buffer),&mut buff_len) },
        _ => unsafe { GetUserNameExW(NameSamCompatible,Some(lp_username_buffer),&mut buff_len) }
    };
    let username_buffer_final = unsafe { slice::from_raw_parts(lp_username_buffer.0, buff_len as usize) };
    let username_str = String::from_utf16_lossy(&username_buffer_final);

    match unsafe { RevertToSelf() } {
        Ok(()) => {},
        Err(e) => return Err(e.message().into())
    }
    
    match unsafe { CloseHandle(h_token) } {
        Ok(()) => {},
        Err(e) => return Err(e.message().into())
    }

    if result != true {
        let error = unsafe{ GetLastError() };
        return Err(format!("Unable to get Username, error code: {:?}", error).into());
    }


    let azure_ad_object_id = if user_type == "AzureAD" {
        convert_azure_ad_sid_to_object_id(&user_sid)
    } else {
        None
    };


    Ok(Some(CurrentUserInfo {
        sid: user_sid,
        username: username_str,
        user_type,
        azure_ad_object_id, // Include the Azure AD Object ID if available
    }))
}