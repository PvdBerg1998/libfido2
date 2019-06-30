#![allow(dead_code)]

mod assertion;
mod cbor_info;
mod credential;
mod device;
mod device_list;
mod ffi;

pub use cbor_info::*;
pub use credential::*;
pub use device::*;
pub use device_list::*;

use ffi::NonNull;
use libfido2_sys::*;
use std::{error, ffi::CStr, fmt, os::raw, str};

const FIDO_DEBUG: raw::c_int = libfido2_sys::FIDO_DEBUG as raw::c_int;
const FIDO_OK: raw::c_int = libfido2_sys::FIDO_OK as raw::c_int;

type Result<T> = std::result::Result<T, FidoError>;

/// The entry point of the library.
/// All access to FIDO2 dongles goes through methods of this struct.
pub struct Fido {
    // Each thread must call fido_init, so Fido must be !Send !Sync
    // Can be replaced with negative trait impl when it is stable
    _private: *const (),
}

impl Fido {
    /// Initializes the FIDO2 library.
    pub fn new(debug: bool) -> Self {
        unsafe {
            if debug {
                fido_init(FIDO_DEBUG);
            } else {
                fido_init(0);
            }
        }
        Fido { _private: &() }
    }

    /// Opens a new [`Device`] located at [`path`].
    ///
    /// [`Device`]: struct.Device.html
    /// [`path`]: struct.DevicePath.html
    pub fn new_device(&self, path: DevicePath<'_>) -> Result<Device> {
        unsafe {
            // Allocate closed device
            let mut device = Device {
                raw: NonNull::new(fido_dev_new()).unwrap(),
            };

            // Try to open the device
            match fido_dev_open(device.raw.as_ptr_mut(), path.0.as_ptr()) {
                FIDO_OK => Ok(device),
                err => Err(FidoError(err)),
            }
        }
    }

    /// Creates a new [`CredentialCreator`].
    ///
    /// # Remarks
    /// - Some authenticators may require the `RESIDENT_KEY` option for certain `CredentialType`'s.
    ///
    /// [`CredentialCreator`]: struct.CredentialCreator.html
    pub fn new_credential_creator(
        &self,
        data: CredentialCreationData<'_>,
    ) -> Result<CredentialCreator> {
        unsafe {
            CredentialCreator::new(
                Credential {
                    raw: NonNull::new(fido_cred_new()).unwrap(),
                },
                data,
            )
        }
    }

    /// Detects any connected FIDO2 devices and returns them as a [`DeviceList`].
    ///
    /// # Arguments
    /// - `max_length`: The maximum amount of devices to list.
    ///
    /// [`DeviceList`]: struct.DeviceList.html
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
                    device_list.raw.as_ptr_mut(),
                    max_length,
                    &mut device_list.found as *mut _
                ),
                FIDO_OK
            );

            device_list
        }
    }
}

/// Contains a FIDO2 error.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct FidoError(raw::c_int);

impl FidoError {
    pub(crate) fn as_str(&self) -> &'static str {
        unsafe {
            let error_str = fido_strerr(self.0);
            assert!(!error_str.is_null());
            str::from_utf8_unchecked(CStr::from_ptr(error_str).to_bytes())
        }
    }
}

impl error::Error for FidoError {}

impl fmt::Debug for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FidoError")
            .field(&self.as_str() as &dyn fmt::Debug)
            .finish()
    }
}

impl fmt::Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
