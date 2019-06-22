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
        let raw = unsafe { fido_dev_new() };
        let open_result = unsafe {
            fido_dev_open(raw, path.borrow().as_ptr())
        };
        if open_result != FIDO_OK {
            return Err(FidoError(open_result));
        }
        Ok(Device {
            raw: NonNull::new(raw).expect("Unable to allocate memory for Device"),
        })
    }
}

pub struct Device {
    raw: NonNull<fido_dev>,
}

impl Drop for Device {
    fn drop(&mut self) {
        let mut raw = self.raw.as_ptr();
        unsafe {
            // This can return an error
            let _ = fido_dev_close(raw);
            fido_dev_free(&mut raw as *mut _);
            assert!(raw.is_null(), "Device was not freed");
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FidoError(raw::c_int);
