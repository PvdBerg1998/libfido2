use libfido2_sys::*;
use std::{
    collections::HashMap, ffi::CStr, iter::FromIterator, os::raw::c_char, ptr::NonNull, slice,
};

#[derive(PartialEq, Eq)]
pub struct CBORData {
    pub(crate) raw: NonNull<fido_cbor_info>,
}

impl CBORData {
    pub fn info<'a>(&'a self) -> CBORInformation<'a> {
        unsafe {
            let cbor_info = self.raw.as_ptr();

            let aag_uid = fido_cbor_info_aaguid_ptr(cbor_info);
            let aag_uid = if aag_uid.is_null() {
                None
            } else {
                let len = fido_cbor_info_aaguid_len(cbor_info);
                Some(slice::from_raw_parts(aag_uid, len))
            };

            let pin_protocols = fido_cbor_info_protocols_ptr(cbor_info);
            let pin_protocols = if pin_protocols.is_null() {
                None
            } else {
                let len = fido_cbor_info_protocols_len(cbor_info);
                Some(slice::from_raw_parts(pin_protocols, len))
            };

            let extensions = fido_cbor_info_extensions_ptr(cbor_info);
            let extensions = if extensions.is_null() {
                None
            } else {
                let len = fido_cbor_info_extensions_len(cbor_info);
                Some(convert_cstr_array_ptr(extensions, len))
            };

            let ctap_versions = fido_cbor_info_versions_ptr(cbor_info);
            let ctap_versions = if ctap_versions.is_null() {
                None
            } else {
                let len = fido_cbor_info_versions_len(cbor_info);
                Some(convert_cstr_array_ptr(ctap_versions, len))
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

unsafe fn convert_cstr_array_ptr<'a>(array: *mut *mut c_char, len: usize) -> Box<[&'a CStr]> {
    slice::from_raw_parts(array, len)
        .iter()
        .map(|ptr| {
            assert!(!ptr.is_null());
            CStr::from_ptr(*ptr)
        })
        .collect::<Vec<&'a CStr>>()
        .into_boxed_slice()
}

impl Drop for CBORData {
    fn drop(&mut self) {
        unsafe {
            let mut cbor_info = self.raw.as_ptr();
            fido_cbor_info_free(&mut cbor_info as *mut _);
            assert!(cbor_info.is_null());
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CBORInformation<'a> {
    pub aag_uid: Option<&'a [u8]>,
    pub pin_protocols: Option<&'a [u8]>,
    pub extensions: Option<Box<[&'a CStr]>>,
    pub ctap_versions: Option<Box<[&'a CStr]>>,
    pub options: HashMap<&'a CStr, bool>,
}
