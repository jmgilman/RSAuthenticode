use crate::bindings::Windows::Win32::Foundation::{HANDLE, HWND, PWSTR};
use crate::bindings::Windows::Win32::Security::Cryptography::Core::*;
use crate::bindings::Windows::Win32::Security::*;
use crate::error::APIError;
use std::os::windows::prelude::{OsStrExt, OsStringExt};
use std::path::Path;
use windows::Guid;

pub struct AuthenticodeData {
    data: WINTRUST_DATA,
    cert: *mut CERT_CONTEXT,
}

#[derive(Debug)]
pub struct CertData {
    common_name: Option<String>,
    organization: Option<String>,
    organization_unit: Option<String>,
    country: Option<String>,
}

pub enum CertType {
    SUBJECT,
    ISSUER,
}

impl AuthenticodeData {
    pub fn new(file_path: &str) -> Result<AuthenticodeData, APIError> {
        // Build path
        let path = Path::new(file_path);
        let mut b_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        b_path.push(0);

        // Build API data
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PWSTR(b_path.as_mut_ptr()),
            hFile: HANDLE::NULL,
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WINTRUST_DATA_UICHOICE(WTD_UI_NONE.0),
            fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(WTD_REVOKE_NONE.0),
            dwUnionChoice: WINTRUST_DATA_UNION_CHOICE(WTD_CHOICE_FILE.0),
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info as *mut _,
            },
            dwStateAction: WINTRUST_DATA_STATE_ACTION(WTD_STATEACTION_VERIFY.0),
            hWVTStateData: HANDLE::NULL,
            pwszURLReference: PWSTR(std::ptr::null_mut()),
            dwProvFlags: 8192 | 32 | 2,
            dwUIContext: WINTRUST_DATA_UICONTEXT(WTD_UICONTEXT_EXECUTE.0),
            pSignatureSettings: std::ptr::null_mut(),
        };

        let mut action = AuthenticodeData::action();

        // Call API
        let result = unsafe { WinVerifyTrust(HWND::NULL, &mut action, &mut data as *mut _ as _) };

        if result != 0 {
            return Err(APIError::ValidationFailed);
        }

        // Get pointer to leaf certificate
        let cert_ptr: _;
        unsafe {
            let cert_data = WTHelperProvDataFromStateData(data.hWVTStateData);
            let signer = WTHelperGetProvSignerFromChain(cert_data, 0, false, 0);
            let cert = WTHelperGetProvCertFromChain(signer, 0);
            cert_ptr = cert.as_ref().unwrap().pCert;
        };

        Ok(AuthenticodeData {
            data: data,
            cert: cert_ptr,
        })
    }

    pub fn read_issuer_cert(&self) -> CertData {
        CertData {
            common_name: self.read_cert_data("2.5.4.3", CertType::ISSUER),
            organization: self.read_cert_data("2.5.4.10", CertType::ISSUER),
            organization_unit: self.read_cert_data("2.5.4.11", CertType::ISSUER),
            country: self.read_cert_data("2.5.4.6", CertType::ISSUER),
        }
    }

    pub fn read_subject_cert(&self) -> CertData {
        CertData {
            common_name: self.read_cert_data("2.5.4.3", CertType::SUBJECT),
            organization: self.read_cert_data("2.5.4.10", CertType::SUBJECT),
            organization_unit: self.read_cert_data("2.5.4.11", CertType::SUBJECT),
            country: self.read_cert_data("2.5.4.6", CertType::SUBJECT),
        }
    }

    fn read_cert_data(&self, oid: &str, ty: CertType) -> Option<String> {
        let key = std::ffi::CString::new(oid).unwrap();
        let flag = match ty {
            CertType::ISSUER => CERT_NAME_ISSUER_FLAG,
            CertType::SUBJECT => 0,
        };
        let len = unsafe {
            CertGetNameStringW(
                self.cert,
                CERT_NAME_ATTR_TYPE,
                flag,
                key.as_bytes_with_nul().as_ptr() as _,
                PWSTR(std::ptr::null_mut()),
                0,
            )
        };

        if len == 1 {
            return None;
        }

        let mut buf = vec![0; len as usize];
        let len = unsafe {
            CertGetNameStringW(
                self.cert,
                CERT_NAME_ATTR_TYPE,
                0,
                key.as_ptr() as _,
                PWSTR(buf.as_mut_ptr()),
                buf.len() as _,
            )
        };

        Some(
            std::ffi::OsString::from_wide(&buf[..len as usize - 1])
                .into_string()
                .unwrap(),
        )
    }

    fn action() -> Guid {
        // WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        Guid::from_values(
            0xaac56b,
            0xcd44,
            0x11d0,
            [0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
        )
    }
}

impl Drop for AuthenticodeData {
    fn drop(&mut self) {
        let mut action = AuthenticodeData::action();
        self.data.dwStateAction = WINTRUST_DATA_STATE_ACTION(WTD_STATEACTION_CLOSE.0);
        unsafe { WinVerifyTrust(HWND::NULL, &mut action, &mut self.data as *mut _ as _) };
    }
}
