use crate::nonnull::NonNull;
use libfido2_sys::*;
use std::{collections::HashMap, ffi::CStr, iter::FromIterator, os::raw::c_char, slice, str};

/// Owns additional data stored as CBOR on a device.
#[derive(PartialEq, Eq)]
pub struct CBORData {
    pub(crate) raw: NonNull<fido_cbor_info>,
}

impl CBORData {
    /// Creates a reference of the owned data.
    ///
    /// # Remarks
    /// - This performs some FFI calls and data conversion and is not zero-cost.
    pub fn info<'a>(&'a self) -> CBORInformation<'a> {
        unsafe {
            let cbor_info = self.raw.as_ptr();

            let aag_uid = fido_cbor_info_aaguid_ptr(cbor_info);
            let aag_uid = if aag_uid.is_null() {
                &[]
            } else {
                let len = fido_cbor_info_aaguid_len(cbor_info);
                slice::from_raw_parts(aag_uid, len)
            };

            let pin_protocols = fido_cbor_info_protocols_ptr(cbor_info);
            let pin_protocols = if pin_protocols.is_null() {
                &[]
            } else {
                let len = fido_cbor_info_protocols_len(cbor_info);
                slice::from_raw_parts(pin_protocols, len)
            };

            let extensions = fido_cbor_info_extensions_ptr(cbor_info);
            let extensions = if extensions.is_null() {
                Box::new([])
            } else {
                let len = fido_cbor_info_extensions_len(cbor_info);
                convert_cstr_array_ptr(extensions, len)
            };

            let ctap_versions = fido_cbor_info_versions_ptr(cbor_info);
            let ctap_versions = if ctap_versions.is_null() {
                Box::new([])
            } else {
                let len = fido_cbor_info_versions_len(cbor_info);
                convert_cstr_array_ptr(ctap_versions, len)
            };

            let option_names = fido_cbor_info_options_name_ptr(cbor_info);
            let options = if option_names.is_null() {
                HashMap::with_capacity(0)
            } else {
                let len = fido_cbor_info_options_len(cbor_info);

                let names = convert_cstr_array_ptr(option_names, len);
                let values = fido_cbor_info_options_value_ptr(cbor_info);
                assert!(!values.is_null());
                let values = slice::from_raw_parts(values, len);

                HashMap::from_iter(
                    names
                        .iter()
                        .zip(values)
                        .map(|(name, value)| (*name, *value)),
                )
            };

            CBORInformation {
                aag_uid,
                pin_protocols,
                extensions,
                ctap_versions,
                options,
            }
        }
    }
}

/// Converts a `*mut *mut c_char` to a boxed array of `&str`s.
///
/// # Unsafety
/// - The `array` pointer must be valid.
/// - Contained strings must be valid UTF-8.
unsafe fn convert_cstr_array_ptr<'a>(array: *mut *mut c_char, len: usize) -> Box<[&'a str]> {
    slice::from_raw_parts(array, len)
        .iter()
        .map(|ptr| {
            assert!(!ptr.is_null());
            str::from_utf8_unchecked(CStr::from_ptr(*ptr).to_bytes())
        })
        .collect::<Vec<&'a str>>()
        .into_boxed_slice()
}

// libfido2_sys guarantees this.
unsafe impl Send for CBORData {}
unsafe impl Sync for CBORData {}

impl Drop for CBORData {
    fn drop(&mut self) {
        unsafe {
            let mut cbor_info = self.raw.as_ptr_mut();
            fido_cbor_info_free(&mut cbor_info as *mut _);
            assert!(cbor_info.is_null());
        }
    }
}

/// Information stored as CBOR on a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CBORInformation<'a> {
    pub aag_uid: &'a [u8],
    pub pin_protocols: &'a [u8],
    pub extensions: Box<[&'a str]>,
    pub ctap_versions: Box<[&'a str]>,
    pub options: HashMap<&'a str, bool>,
}
