mod bindings {
    windows::include_bindings!();
}

use bindings::Windows::Win32::Foundation::{HANDLE, HWND, PWSTR};
use bindings::Windows::Win32::Security::*;
use std::os::windows::prelude::OsStrExt;
use std::path::Path;
use windows::{Guid};

fn main() {
    let path = Path::new(r#"C:\Users\Josh\Downloads\mpam-feX64.exe"#);
    let mut b_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    b_path.push(0);

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

    // WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    let mut action = Guid::from_values(0xaac56b, 0xcd44, 0x11d0, [0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee ]);
    let r = unsafe {WinVerifyTrust(HWND::NULL, &mut action, &mut data as *mut _ as _) };

    // Close handle
    data.dwStateAction = WINTRUST_DATA_STATE_ACTION(WTD_STATEACTION_CLOSE.0);
    let rc = unsafe {WinVerifyTrust(HWND::NULL, &mut action, &mut data as *mut _ as _) };

    println!("{}", r);
    println!("{}", rc);
}
