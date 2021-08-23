fn main() {
    windows::build! {
        Windows::Win32::Foundation::{HANDLE, HWND, TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE, PWSTR},
        Windows::Win32::Security::{
            WINTRUST_DATA, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION,
            WINTRUST_DATA_UICHOICE, WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UNION_CHOICE,
            WINTRUST_FILE_INFO, WINTRUST_SIGNATURE_SETTINGS, WinVerifyTrust,
            WTHelperProvDataFromStateData, WTHelperGetProvSignerFromChain,
            WTHelperGetProvCertFromChain},
            Windows::Win32::Security::Cryptography::Core::{CertGetNameStringW, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG},
    };
}
