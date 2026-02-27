use std::{env, sync::mpsc::Receiver};
use tokio::{time::{Duration, interval}};
use tracing::{error, info, warn};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher, Result,
};



mod windows_api;
mod service_helpers;

use crate::windows_api::event_watcher::{Event};

// Main service entry point
define_windows_service!(ffi_service_main, service_main);
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        error!("Service failed: {:?}", e);
    }
}



fn run_service() -> Result<()> {
    // Set up logging
    let mut path = env::current_exe().unwrap_or("C:\\ProgramData\\cua\\cua.exe".into());
    _ = path.pop();
    _ = path.pop();
    let file_appender = tracing_appender::rolling::never(path, "cua.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .json()
        .with_target(true)          // Include the module path
        .with_current_span(true)    // Include the current span
        .with_span_list(true)     
        .flatten_event(true)  // Include the full span hierarchy
        .with_writer(non_blocking)
        .init();

    // Define service status
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let status_handle = service_control_handler::register(
        service_helpers::config::SERVICE_NAME,
        move |control_event| match control_event {
            ServiceControl::Stop => {
                shutdown_tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    )?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None
    })?;
    // Main service loop
    info!(action="service_startup", "Service is running...");
    service_loop(shutdown_rx);
    info!(action="service_stopped", "Service is stopping...");
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::new(0, 0),
        process_id: None
    })?;
    Ok(())
}

fn service_loop(shutdown_rx: Receiver<()>) {
    const LOGON_LOGOFF_EVENT_XPATH: &str = "Event[((System[(EventID='4624')] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']) or System[(EventID='4647')])]";
    const WHITELISTED_SID: [&str; 2] = ["S-1-5-96", "S-1-5-90"];

    let logon_logoff_event_callback = Box::new(|event: Event| -> () {
        match event.event_data {
            Some(event_data) => {
                let sid = event_data.get_value("TargetUserSid");
                let username = event_data.get_value("TargetUserName");
                let logon_type = event_data.get_value("LogonType");
                let event_id_type= event.system.get_event_id_type().to_string();
                if let Some(sid) = sid {
                    if !WHITELISTED_SID.iter().any(|ignore_sid| {sid.starts_with(ignore_sid)}) {
                        info!(action="logon_logoff_event", event_type=event_id_type, user_sid = sid, username = username, logon_type=logon_type);
                        windows_api::collect_logs();
                    }
                }
            },
            None => warn!(action="logon_logoff_event", "No Event Data for Event ID: {}", event.system.event_id)
        };
    });
    let logon_loggoff_event_watcher = windows_api::event_watcher::register_event_watcher(&LOGON_LOGOFF_EVENT_XPATH, Some(Duration::from_millis(100)),logon_logoff_event_callback, );

    match logon_loggoff_event_watcher {
        Ok(_) => info!(action="logon_watcher_start", "Logon watcher started sucessfully"),
        Err(e) => error!(action="logon_watcher_start", "Error starting logon watcher - {}", e)
    };

    tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()
    .unwrap()
    .block_on(async {
        let shutdown = tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                if shutdown_rx.try_recv().is_ok() {
                    info!(action="service_shutdown", "Shutdown signal received");
                    break;
                }
            }
        });

        tokio::select! {
            _ = shutdown => {}
        };

    });
}

fn main() -> Result<()> {
    service_dispatcher::start(service_helpers::config::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}
