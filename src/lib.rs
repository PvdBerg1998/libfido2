#![allow(dead_code)]

pub mod device;
pub mod info;

use device::Device;
use info::DeviceList;
use libfido2_sys::*;
use std::{
    borrow::Borrow,
    ffi::CStr,
    fmt::{self, Debug},
    os::raw,
    ptr::NonNull,
    sync::Once,
};

const FIDO_DEBUG: raw::c_int = libfido2_sys::FIDO_DEBUG as raw::c_int;
const FIDO_OK: raw::c_int = libfido2_sys::FIDO_OK as raw::c_int;

static LIB_INITIALIZED: Once = Once::new();

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

    pub fn new_device<S: Borrow<CStr>>(&self, path: S) -> Result<Device, FidoError> {
        // Allocate closed device
        let raw = unsafe { fido_dev_new() };
        assert!(!raw.is_null());

        // Try to open it
        let open_result = unsafe { fido_dev_open(raw, path.borrow().as_ptr()) };
        if open_result != FIDO_OK {
            return Err(FidoError(open_result));
        }

        Ok(Device {
            raw: unsafe { NonNull::new_unchecked(raw) },
        })
    }

    pub fn detect_devices(&self, max_length: usize) -> DeviceList {
        // Allocate empty device list
        let device_list = unsafe { fido_dev_info_new(max_length) };
        assert!(!device_list.is_null());

        // Fill list with found devices
        let mut found_devices: usize = 0;
        unsafe {
            // Always returns FIDO_OK
            let _ = fido_dev_info_manifest(device_list, max_length, &mut found_devices as *mut _);
        }

        DeviceList {
            raw: unsafe { NonNull::new_unchecked(device_list) },
            length: max_length,
            found: found_devices,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct FidoError(raw::c_int);

impl Debug for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let error_str = fido_strerr(self.0);
            assert!(!error_str.is_null());
            f.write_str(CStr::from_ptr(error_str).to_str().unwrap())
        }
    }
}
