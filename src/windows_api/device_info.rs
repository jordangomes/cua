use std::collections::HashMap;

use bytes::Bytes;
use windows_registry::*;
use x509_certificate::{X509Certificate};
use bcder::Oid;

#[derive(Debug)]
pub struct EntraJoinInfo {
    pub tenant_id: String,
    pub device_id: String,
    pub registered_user: String,
}

const CERT_REG_PATH: &str = "SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates";
const TENANT_JOIN_REG_PATH: &str = "SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo";

const DC_OID: Oid = Oid(Bytes::from_static(b"\t\x92&\x89\x93\xf2,d\x01\x19"));
const CN_OID: Oid = Oid(Bytes::from_static(b"U\x04\x03"));

pub fn get_entra_join_info() -> Result<Vec<EntraJoinInfo>> {
    let mut results: Vec<EntraJoinInfo> = Vec::new();
    let cerificates_regkey = LOCAL_MACHINE.open(CERT_REG_PATH)?;
    let certificate_keys = cerificates_regkey.keys()?;

    let mut certificate_map: HashMap<String, String> = HashMap::new();
    for key in certificate_keys {
        let path = CERT_REG_PATH.to_owned() + "\\" + &key;
        let certificate_key = LOCAL_MACHINE.open(path)?;
        let certificate_blob_value = certificate_key.get_value("Blob")?;
        let certificate_blob_bytes: Vec<u8> = certificate_blob_value.iter().map(|&x| x).collect();

        // Stupid magic shit to find the x509 certificate in the Certificate Blob - https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/
        let certificate_start_sequence:[u8; 8] = [0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let mut certificate_window = certificate_blob_bytes.windows(8);
        let mut certificate_bytes:Vec<u8> = Vec::new();
        if let Some(window) = certificate_window.position(|w| w == certificate_start_sequence) {
            let start = window + certificate_start_sequence.len() + 4; // skip to the window location plus the starting sequence + 4 bytes for length
            certificate_bytes.extend_from_slice(&certificate_blob_bytes[start..]); // Collect everything after the starting sequence
        }

        // 
        if let Ok(parsed_certificate) = X509Certificate::from_der(certificate_bytes) {
            let certificate_subject_name = parsed_certificate.subject_name();
            let dc_res = certificate_subject_name.find_first_attribute_string(DC_OID);
            let cn_res= certificate_subject_name.find_first_attribute_string(CN_OID);
            match (dc_res, cn_res) {
                (Ok(Some(dc)), Ok(Some(cn))) => {
                    certificate_map.insert(dc, cn);
                }
                _ => {}
            } ;
        }

    }

    let tenant_join_key = LOCAL_MACHINE.open(TENANT_JOIN_REG_PATH)?;
    let tenant_join_keys = tenant_join_key.keys()?;

    for key in tenant_join_keys {
        let path = TENANT_JOIN_REG_PATH.to_owned() + "\\" + &key;
        let tenant_join_info = LOCAL_MACHINE.open(path)?;
        let tenant_id = tenant_join_info.get_string("TenantId")?;
        let registered_user = tenant_join_info.get_string("UserEmail")?;
        let device_id_default = &"".to_string();
        let device_id: &String = certificate_map.get(&tenant_id).unwrap_or(device_id_default);

        results.push(EntraJoinInfo {
            tenant_id,
            device_id: device_id.to_owned(),
            registered_user,
        });
    }

    Ok(results)
}
