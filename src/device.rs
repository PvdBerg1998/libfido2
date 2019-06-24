use crate::{cbor_info::CBORData, FidoError, Result, FIDO_OK};
use bitflags::bitflags;
use libfido2_sys::*;
use std::{ffi::CStr, ptr::NonNull};

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
            let cbor_info = CBORData {
                raw: NonNull::new(fido_cbor_info_new()).unwrap(),
            };

            // Request CBOR information
            // NB. This requires a *mut Device, so we require &mut self
            let result = fido_dev_get_cbor_info(self.raw.as_ptr(), cbor_info.raw.as_ptr());
            if result != FIDO_OK {
                return Err(FidoError(result));
            }

            Ok(cbor_info)
        }
    }
}

unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let mut device = self.raw.as_ptr();
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
        self.0.to_str().unwrap()
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
