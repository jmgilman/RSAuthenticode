use crate::bindings::Windows::Win32::Storage::FileSystem::*;
use std::ffi::c_void;
use std::mem::MaybeUninit;

pub fn read_version(path: &str) -> Option<String> {
    let mut version_handle = 0;
    let version_size = unsafe { GetFileVersionInfoSizeA(path, &mut version_handle) };
    let mut version_data: Vec<u8> = vec![0u8; version_size as usize];

    let result = unsafe { GetFileVersionInfoA(path, 0, version_size, version_data.as_mut_ptr() as *mut c_void)};
    if result.as_bool() {
        let mut buffer = MaybeUninit::zeroed();
        let mut buffer_size = 0;

        let version_exists = unsafe {
            VerQueryValueA(version_data.as_ptr() as *const c_void, r#"\"#, buffer.as_mut_ptr(), &mut buffer_size)
        };

        if version_exists.as_bool() {
            let data = unsafe { buffer.assume_init() };
            let fixed_file_info: *mut VS_FIXEDFILEINFO = data.cast();

            unsafe {
                if (*fixed_file_info).dwSignature == 0xfeef04bd {
                    return Some(format!(
                        "{}.{}.{}.{}",
                        ((*fixed_file_info).dwFileVersionMS >> 16) & 0xffff,
                        ((*fixed_file_info).dwFileVersionMS >> 0) & 0xffff,
                        ((*fixed_file_info).dwFileVersionLS >> 16) & 0xffff,
                        ((*fixed_file_info).dwFileVersionLS >> 0) & 0xffff,
                    ));
                }
            };
        }
    }

    None
}