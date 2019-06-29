use crate::ffi::NonNull;
use libfido2_sys::*;
use std::{ffi::CStr, slice};

pub struct Credential {
    pub(crate) raw: NonNull<fido_cred>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef<'a> {
    format: Option<&'a CStr>,
    auth_data: Option<&'a [u8]>,
    client_data_hash: Option<&'a [u8]>,
    id: Option<&'a [u8]>,
    public_key: Option<&'a [u8]>,
    signature: Option<&'a [u8]>,
    x509_certificate: Option<&'a [u8]>,
}

impl Credential {
    pub fn as_ref<'a>(&'a self) -> CredentialRef<'a> {
        unsafe {
            let credential = self.raw.as_ptr();

            let format = fido_cred_fmt(credential)
                .as_ref()
                .map(|ptr| CStr::from_ptr(ptr));

            let auth_data = fido_cred_authdata_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_authdata_len(credential)));

            let client_data_hash = fido_cred_clientdata_hash_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_clientdata_hash_len(credential)));

            let id = fido_cred_id_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_id_len(credential)));

            let public_key = fido_cred_pubkey_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_pubkey_len(credential)));

            let signature = fido_cred_sig_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_sig_len(credential)));

            let x509_certificate = fido_cred_x5c_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_x5c_len(credential)));

            CredentialRef {
                format,
                auth_data,
                client_data_hash,
                id,
                public_key,
                signature,
                x509_certificate,
            }
        }
    }
}

// libfido2_sys guarantees this.
unsafe impl Send for Credential {}
unsafe impl Sync for Credential {}

impl Drop for Credential {
    fn drop(&mut self) {
        unsafe {
            let mut credential = self.raw.as_ptr_mut();
            fido_cred_free(&mut credential as *mut _);
            assert!(credential.is_null());
        }
    }
}
