fn main() {
    windows::build! {
        Windows::Win32::Foundation::{HANDLE, HWND, PWSTR},
        Windows::Win32::Security::{
            WINTRUST_DATA, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION, 
            WINTRUST_DATA_UICHOICE, WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UNION_CHOICE, 
            WINTRUST_FILE_INFO, WINTRUST_SIGNATURE_SETTINGS, WinVerifyTrust},
    };
}