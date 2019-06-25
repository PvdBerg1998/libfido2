use crate::{cbor_info::CBORData, nonnull::NonNull, FidoError, Result, FIDO_OK};
use bitflags::bitflags;
use libfido2_sys::*;
use std::{ffi::CStr, str};

#[derive(PartialEq, Eq)]
pub struct Device {
    pub(crate) raw: NonNull<fido_dev>,
}

impl Device {
    pub fn is_fido2(&self) -> bool {
        unsafe { fido_dev_is_fido2(self.raw.as_ptr()) }
    }

    pub fn ctap_hid_info(&self) -> CTAPHIDInfo {
        unsafe {
            let device = self.raw.as_ptr();

            let protocol = fido_dev_protocol(device);
            let major = fido_dev_major(device);
            let minor = fido_dev_minor(device);
            let build = fido_dev_build(device);
            let flags = fido_dev_flags(device);
            let flags = CTAPHIDCapabilities::from_bits_truncate(flags);

            CTAPHIDInfo {
                protocol,
                major,
                minor,
                build,
                capabilities: flags,
            }
        }
    }

    pub fn request_cbor_data(&mut self) -> Result<CBORData> {
        unsafe {
            // Allocate empty CBOR info (called CBORData since the information has its own wrapper struct)
            let mut cbor_info = CBORData {
                raw: NonNull::new(fido_cbor_info_new()).unwrap(),
            };

            // Request CBOR information
            match fido_dev_get_cbor_info(self.raw.as_ptr_mut(), cbor_info.raw.as_ptr_mut()) {
                FIDO_OK => Ok(cbor_info),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_pin(&mut self, new_pin: &CStr, old_pin: &CStr) -> Result<()> {
        unsafe {
            match fido_dev_set_pin(self.raw.as_ptr_mut(), new_pin.as_ptr(), old_pin.as_ptr()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe {
            match fido_dev_reset(self.raw.as_ptr_mut()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn retry_count(&mut self) -> Result<i32> {
        unsafe {
            let mut amount = 0;
            match fido_dev_get_retry_count(self.raw.as_ptr_mut(), &mut amount as *mut _) {
                FIDO_OK => Ok(amount),
                err => Err(FidoError(err)),
            }
        }
    }
}

unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let mut device = self.raw.as_ptr_mut();
            // This can return an error
            // If we are not opened yet, this is a NOOP
            let _ = fido_dev_close(device);
            fido_dev_free(&mut device as *mut _);
            assert!(device.is_null());
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DevicePath<'a>(pub(crate) &'a CStr);

impl<'a> DevicePath<'a> {
    pub fn from_cstr(s: &'a CStr) -> Self {
        DevicePath(s)
    }

    pub fn to_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(self.0.to_bytes()) }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CTAPHIDInfo {
    pub protocol: u8,
    pub major: u8,
    pub minor: u8,
    pub build: u8,
    pub capabilities: CTAPHIDCapabilities,
}

bitflags! {
    pub struct CTAPHIDCapabilities: u8 {
        const CBOR = FIDO_CAP_CBOR as u8;
        const NMSG = FIDO_CAP_NMSG as u8;
        const WINK = FIDO_CAP_WINK as u8;
    }
}
