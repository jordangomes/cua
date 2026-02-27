use tracing::{error, info};

pub mod device_info;
pub mod user_info;
pub mod event_watcher;


pub fn collect_logs() {
    let device_info = device_info::get_entra_join_info();
    match device_info {
        Err(error) => {
            error!(action = "tenant_info", "Errror retrieving entra join info - {}", error.message());
        },
        Ok(results) => {
            for result in results {
                info!(action = "tenant_info", tenant_id = result.tenant_id, device_id = result.device_id, registered_user = result.registered_user);
            }
        }
    }

    match user_info::get_user_info() {
        Ok(Some(current_user_info)) => {
            match current_user_info.azure_ad_object_id {
                Some(azure_ad_object_id) => info!(
                    action = "current_user_info", 
                    user_sid = current_user_info.sid, 
                    username = current_user_info.username, 
                    user_type = current_user_info.user_type, 
                    azure_ad_object_id = azure_ad_object_id),
                None => info!(
                    action = "current_user_info", 
                    user_sid = current_user_info.sid, 
                    username = current_user_info.username, 
                    user_type = current_user_info.user_type)
            };
        },
        Ok(None) => { info!(action = "current_user_info", "No user currently logged in"); }
        Err(err) => {
            error!(action = "current_user_info", "Unable to retrieve user info: {}", err);
        }
    };
}