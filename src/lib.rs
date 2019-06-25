#![allow(dead_code)]

pub mod cbor_info;
pub mod device;
pub mod device_list;

use device::{Device, DevicePath};
use device_list::DeviceList;
use libfido2_sys::*;
use std::{error, ffi::CStr, fmt, os::raw, ptr::NonNull, str, sync::Once};

const FIDO_DEBUG: raw::c_int = libfido2_sys::FIDO_DEBUG as raw::c_int;
const FIDO_OK: raw::c_int = libfido2_sys::FIDO_OK as raw::c_int;

static LIB_INITIALIZED: Once = Once::new();

type Result<T> = std::result::Result<T, FidoError>;

// Use a struct with methods to make sure `fido_init` gets called
pub struct Fido {
    _private: (),
}

impl Fido {
    pub fn new() -> Self {
        LIB_INITIALIZED.call_once(|| unsafe {
            // Argument can be 0 for no debugging, or FIDO_DEBUG for debugging
            fido_init(0);
        });

        Fido { _private: () }
    }

    pub fn new_device(&self, path: DevicePath<'_>) -> Result<Device> {
        unsafe {
            // Allocate closed device
            let device = Device {
                raw: NonNull::new(fido_dev_new()).unwrap(),
            };

            // Try to open the device
            let open_result = fido_dev_open(device.raw.as_ptr(), path.0.as_ptr());
            if open_result != FIDO_OK {
                return Err(FidoError(open_result));
            }

            Ok(device)
        }
    }

    pub fn detect_devices(&self, max_length: usize) -> DeviceList {
        unsafe {
            // Allocate empty device list
            let mut device_list = DeviceList {
                raw: NonNull::new(fido_dev_info_new(max_length)).unwrap(),
                length: max_length,
                found: 0,
            };

            // Fill list with found devices
            // This should always return FIDO_OK
            assert_eq!(
                fido_dev_info_manifest(
                    device_list.raw.as_ptr(),
                    max_length,
                    &mut device_list.found as *mut _
                ),
                FIDO_OK
            );

            device_list
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FidoError(raw::c_int);

impl error::Error for FidoError {}

impl fmt::Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let error_str = fido_strerr(self.0);
            assert!(!error_str.is_null());
            f.write_str(str::from_utf8_unchecked(
                CStr::from_ptr(error_str).to_bytes(),
            ))
        }
    }
}
