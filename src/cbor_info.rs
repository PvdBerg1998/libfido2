use crate::ffi::*;
use libfido2_sys::*;
use std::{collections::HashMap, iter::FromIterator, slice, str};

/// Owns additional data stored as CBOR on a device.
#[derive(PartialEq, Eq)]
pub struct CBORData {
    pub(crate) raw: NonNull<fido_cbor_info>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CBORDataRef<'a> {
    pub aag_uid: Option<&'a [u8]>,
    pub pin_protocols: &'a [u8],
    pub extensions: Box<[&'a str]>,
    pub ctap_versions: Box<[&'a str]>,
    pub options: HashMap<&'a str, bool>,
}

impl CBORData {
    pub fn as_ref<'a>(&'a self) -> CBORDataRef<'a> {
        unsafe {
            let cbor_info = self.raw.as_ptr();

            let aag_uid = fido_cbor_info_aaguid_ptr(cbor_info)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cbor_info_aaguid_len(cbor_info)));

            let pin_protocols = fido_cbor_info_protocols_ptr(cbor_info)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cbor_info_protocols_len(cbor_info)))
                .unwrap_or(&[]);

            let extensions = fido_cbor_info_extensions_ptr(cbor_info)
                .as_ref()
                .map(|ptr| convert_cstr_array_ptr(ptr, fido_cbor_info_extensions_len(cbor_info)))
                .unwrap_or(Box::new([]));

            let ctap_versions = fido_cbor_info_versions_ptr(cbor_info)
                .as_ref()
                .map(|ptr| convert_cstr_array_ptr(ptr, fido_cbor_info_versions_len(cbor_info)))
                .unwrap_or(Box::new([]));

            let options = fido_cbor_info_options_name_ptr(cbor_info)
                .as_ref()
                .map(|ptr| convert_cstr_array_ptr(ptr, fido_cbor_info_options_len(cbor_info)))
                .map(|names| {
                    let values = fido_cbor_info_options_value_ptr(cbor_info)
                        .as_ref()
                        .map(|ptr| slice::from_raw_parts(ptr, names.len()))
                        .unwrap();
                    (names, values)
                })
                .map(|(names, values)| {
                    HashMap::from_iter(
                        names
                            .iter()
                            .zip(values)
                            .map(|(name, value)| (*name, *value)),
                    )
                })
                .unwrap_or(HashMap::with_capacity(0));

            CBORDataRef {
                aag_uid,
                pin_protocols,
                extensions,
                ctap_versions,
                options,
            }
        }
    }
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
