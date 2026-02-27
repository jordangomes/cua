mod config;
use std::ffi::OsStr;
use windows_service::service::ServiceAccess;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

fn main() -> windows_service::Result<()>  {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let my_service = manager.open_service(config::SERVICE_NAME, ServiceAccess::START)?;
    my_service.start(&[OsStr::new("")])?;
    Ok(())
}
