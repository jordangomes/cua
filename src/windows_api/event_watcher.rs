use quick_xml::DeError;
use tracing::error;
use std::iter;
use std::os::raw::c_void;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows::core::{Error, HRESULT, PCWSTR, Result, w};
use windows::Win32::System::EventLog::{EvtSubscribe, EvtRender, EVT_SUBSCRIBE_CALLBACK, EVT_SUBSCRIBE_NOTIFY_ACTION, EVT_HANDLE, EvtSubscribeToFutureEvents, EvtSubscribeActionError, EvtSubscribeActionDeliver, EvtRenderEventXml};
use windows::Win32::Foundation::{HANDLE, ERROR_UNHANDLED_EXCEPTION, ERROR_XML_PARSE_ERROR};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Event {
    #[serde(rename = "System")]
    pub system: System,

    #[serde(rename = "EventData")]
    pub event_data: Option<EventData>,
}

#[derive(Debug, Deserialize)]
pub struct System {
    #[serde(rename = "EventID")]
    pub event_id: u32,
}

#[derive(Debug, Deserialize)]
pub struct EventData {
    #[serde(rename = "Data")]
    pub data: Vec<EventDataField>,
}

#[derive(Debug)]
pub enum EventIdType {
    Logon,
    Logoff,
    LogoffInteractive,
    Unknown
}

impl std::fmt::Display for EventIdType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl System {
    pub fn get_event_id_type(&self) -> EventIdType {
        match self.event_id {
            4624 => EventIdType::Logon,
            4634 => EventIdType::Logoff,
            4647 => EventIdType::LogoffInteractive,
            _ => EventIdType::Unknown
        }
    }
}

impl EventData {
    pub fn get_value(&self, field_name: &str) -> Option<String> {
        self.data
            .iter()
            .find(|field| field.name == field_name)
            .map(|field| field.value.clone())
    }
}

#[derive(Debug, Deserialize)]
pub struct EventDataField {
    #[serde(rename = "@Name")]
    name: String,

    #[serde(rename = "$text")]
    value: String,
}

type UserCallback = Box<dyn FnMut(Event) -> ()>;

struct EventSubscriptionContext {
    callback: UserCallback,
    debounce: Option<Duration>,
    last_call: Mutex<Option<Instant>>,
}

pub fn register_event_watcher(xpath: &str, debounce: Option<Duration>, callback: Box<dyn FnMut(Event) -> ()>) -> Result<()> {
    let trampoline_callback: EVT_SUBSCRIBE_CALLBACK = Some(handle_windows_event);
    let session = Some(EVT_HANDLE(0));
    let signal_event = std::ptr::null_mut();

    let bookmark = Some(EVT_HANDLE(0));

    let ctx = Box::new(EventSubscriptionContext {
        callback: callback,
        debounce,
        last_call: Mutex::new(None),
    });
    let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

    let channel_path = w!("Security");

    let query_string_vec = xpath.encode_utf16().chain(iter::once(0u16)).collect::<Vec<u16>>();
    let query = PCWSTR(query_string_vec.as_ptr());

    let event_handle = unsafe { EvtSubscribe(session, Some(HANDLE(signal_event)), PCWSTR(channel_path.as_ptr()), query, bookmark, Some(ctx_ptr), trampoline_callback, EvtSubscribeToFutureEvents.0) };
    match event_handle {
        Err(err) => { Err(err) },
        _ => Ok(())
    }
}

unsafe extern "system" fn handle_windows_event(action: EVT_SUBSCRIBE_NOTIFY_ACTION, context: *const c_void, event: EVT_HANDLE) -> u32 {
    let event_string_result: Result<String> = match action {
        EvtSubscribeActionError => Err(Error::new(HRESULT(event.0 as i32), "Event subscribe action error")),
        EvtSubscribeActionDeliver => get_event_xml_from_handle(event),
        _ => Err(Error::new(HRESULT(ERROR_UNHANDLED_EXCEPTION.0 as i32), format!("Unhandled event subscribe action {:?}", action)))
    };

    let event_result: Result<Event> = match event_string_result {
        Ok(event_xml) => {
            let parsed_xml:std::result::Result<Event, DeError> = quick_xml::de::from_str(&event_xml); 
            match parsed_xml {
                Ok(event) => Ok(event),
                Err(err) => Err(Error::new(HRESULT(ERROR_XML_PARSE_ERROR.0 as i32), format!("Error serializing xml {:?}", err.to_string())))
            }
        },
        Err(error) => Err(error)
    };

    match event_result {
        Ok(event) => {
            let ctx: &mut EventSubscriptionContext = unsafe{ &mut *(context as *mut EventSubscriptionContext) };

            match ctx.debounce {
                None => {
                    // No debouncing — call immediately
                    (ctx.callback)(event)
                }
                Some(duration) => {
                    let now = Instant::now();
                    let mut last_call = ctx.last_call.lock().unwrap();

                    let should_call = match *last_call {
                        None => true, // first event
                        Some(last) => now.duration_since(last) >= duration,
                    };

                    if should_call {
                        *last_call = Some(now);
                        (ctx.callback)(event)
                    }
                }
            }
                
        },
        Err(err) => error!(name="event_watcher", "{}: {:?}", err.message(), err.code())
    };
    0
}

fn get_event_xml_from_handle(event: EVT_HANDLE) -> Result<String> {
    const BUFFER_SIZE: usize = 65_000;
    // Windows uses UTF16 for their strings which means that their strings are 16 bytes wide
    // instead of the normal 8 for rust's UTF8 strings
    let mut buffer: [u16; BUFFER_SIZE] = [0; BUFFER_SIZE];
    let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
    let mut property_value_buffer_used:u32 = 0;
    let mut property_count:u32 = 0;
    let buffer_opt = Some(buffer_ptr);

    // Call Event Render
    unsafe { EvtRender(Some(EVT_HANDLE(0)), event, EvtRenderEventXml.0,BUFFER_SIZE as u32, buffer_opt, &mut property_value_buffer_used, &mut property_count)? };
    Ok(String::from_utf16_lossy(&buffer).trim_matches(char::from(0)).to_string())
}