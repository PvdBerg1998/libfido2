use libfido2_sys::*;
use std::ptr::NonNull;
use std::sync::Once;
use std::ffi::CStr;
use std::borrow::Borrow;
use std::os::raw;

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
            fido_init(FIDO_DEBUG);
        });

        Fido { _private: () }
    }

    pub fn new_device<S: Borrow<CStr>>(path: S) -> Result<Device, FidoError> {
        // Allocate closed device
        let raw = unsafe { fido_dev_new() };
        assert!(!raw.is_null());

        // Try to open it
        let open_result = unsafe {
            fido_dev_open(raw, path.borrow().as_ptr())
        };
        if open_result != FIDO_OK {
            return Err(FidoError(open_result));
        }

        Ok(Device {
            raw: unsafe { NonNull::new_unchecked(raw) },
        })
    }

    pub fn detect_devices(max_length: usize) -> DeviceList {
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
            found: found_devices
        }
    }
}

pub struct DeviceList {
    raw: NonNull<fido_dev_info>,
    length: usize,
    found: usize
}

impl DeviceList {
    pub fn iter_paths<'a>(&'a self) -> impl Iterator<Item = &'a str> {
        let device_list = self.raw.as_ptr();
        (0..self.found).map(move |i| {
            unsafe {
                let device_info = fido_dev_info_ptr(device_list, i);
                assert!(!device_info.is_null());

                let device_path = fido_dev_info_path(device_info);
                assert!(!device_path.is_null());
                CStr::from_ptr(device_path).to_str().expect("Path contains invalid UTF-8")
            }
        })
    }
}

impl Drop for DeviceList {
    fn drop(&mut self) {
        let mut device_list = self.raw.as_ptr();
        unsafe {
            fido_dev_info_free(&mut device_list as *mut _, self.length);
        }
        assert!(device_list.is_null(), "DeviceList was not freed");
    }
}

pub struct Device {
    raw: NonNull<fido_dev>,
}

impl Drop for Device {
    fn drop(&mut self) {
        let mut device = self.raw.as_ptr();
        unsafe {
            // This can return an error
            let _ = fido_dev_close(device);
            fido_dev_free(&mut device as *mut _);
        }
        assert!(device.is_null(), "Device was not freed");
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FidoError(raw::c_int);
