use crate::{ffi::NonNull, FidoError, Result, FIDO_OK};
use bitflags::bitflags;
use libfido2_sys::*;
use std::{error, ffi::CStr, fmt, os::raw, ptr, slice, str::FromStr};

// @TODO: Create types for getters/setters instead of using byte slices
// This is out of scope for now

pub struct Credential {
    pub(crate) raw: NonNull<fido_cred>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef<'a> {
    pub format: Option<&'a CStr>,
    pub auth_data: Option<&'a [u8]>,
    pub client_data_hash: Option<&'a [u8]>,
    pub id: Option<&'a [u8]>,
    pub public_key: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub x509_certificate: Option<&'a [u8]>,
}

pub struct CredentialCreator(pub(crate) Credential);
pub struct CredentialVerifier(pub(crate) Credential);

impl CredentialCreator {
    pub fn set_excluded(&mut self, excluded_ids: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_exclude(
                self.0.raw.as_ptr_mut(),
                excluded_ids as *const _ as *const _,
                excluded_ids.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    /// # Remarks
    /// - This method can only be called once and will return an error afterwards @TODO why?
    pub fn set_type(&mut self, credential_type: CredentialType) -> Result<()> {
        unsafe {
            match fido_cred_set_type(self.0.raw.as_ptr_mut(), credential_type as raw::c_int) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_client_data_hash(&mut self, client_data_hash: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_clientdata_hash(
                self.0.raw.as_ptr_mut(),
                client_data_hash as *const _ as *const _,
                client_data_hash.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_relying_party(&mut self, id: &CStr, name: &CStr) -> Result<()> {
        unsafe {
            match fido_cred_set_rp(self.0.raw.as_ptr_mut(), id.as_ptr(), name.as_ptr()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_user(
        &mut self,
        user_id: &[u8],
        name: &CStr,
        display_name: Option<&CStr>,
        account_image_uri: Option<&CStr>,
    ) -> Result<()> {
        unsafe {
            match fido_cred_set_user(
                self.0.raw.as_ptr_mut(),
                user_id as *const _ as *const _,
                user_id.len(),
                name.as_ptr(),
                display_name.map(CStr::as_ptr).unwrap_or(ptr::null()),
                account_image_uri.map(CStr::as_ptr).unwrap_or(ptr::null()),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_options(&mut self, options: CredentialOptions) -> Result<()> {
        self.0.set_options(options)
    }

    pub fn set_extensions(&mut self, extensions: CredentialExtensions) -> Result<()> {
        self.0.set_extensions(extensions)
    }
}

impl CredentialVerifier {
    pub fn set_format(&mut self, fmt: CredentialFormat) -> Result<()> {
        unsafe {
            match fido_cred_set_fmt(self.0.raw.as_ptr_mut(), fmt.to_ffi()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_auth_data(&mut self, auth_data: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_authdata(
                self.0.raw.as_ptr_mut(),
                auth_data as *const _ as *const _,
                auth_data.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_x509_certificate(&mut self, x509_certificate: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_x509(
                self.0.raw.as_ptr_mut(),
                x509_certificate as *const _ as *const _,
                x509_certificate.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_sig(
                self.0.raw.as_ptr_mut(),
                signature as *const _ as *const _,
                signature.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    pub fn set_options(&mut self, options: CredentialOptions) -> Result<()> {
        self.0.set_options(options)
    }

    pub fn set_extensions(&mut self, extensions: CredentialExtensions) -> Result<()> {
        self.0.set_extensions(extensions)
    }
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

    fn set_options(&mut self, options: CredentialOptions) -> Result<()> {
        unsafe {
            match fido_cred_set_options(
                self.raw.as_ptr_mut(),
                options.contains(CredentialOptions::RESIDENT_KEY),
                options.contains(CredentialOptions::USER_VERIFICATION),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_extensions(&mut self, extensions: CredentialExtensions) -> Result<()> {
        unsafe {
            match fido_cred_set_extensions(self.raw.as_ptr_mut(), extensions.bits()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
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

bitflags! {
    pub struct CredentialExtensions: raw::c_int {
        const HMAC_SECRET = FIDO_EXT_HMAC_SECRET as raw::c_int;
    }
}

bitflags! {
    pub struct CredentialOptions: u8 {
        const RESIDENT_KEY = 1;
        const USER_VERIFICATION = 2;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredentialFormat {
    Fido2,
    FidoU2F,
}

impl CredentialFormat {
    const FIDO2_FORMAT: &'static str = "packed";
    const FIDO2_FORMAT_CSTR: *const raw::c_char = b"packed\0" as *const _ as *const _;
    const FIDO_U2F_FORMAT: &'static str = "fido-u2f";
    const FIDO_U2F_FORMAT_CSTR: *const raw::c_char = b"fido-u2f\0" as *const _ as *const _;

    pub(crate) fn to_ffi(&self) -> *const raw::c_char {
        match self {
            CredentialFormat::Fido2 => Self::FIDO2_FORMAT_CSTR,
            CredentialFormat::FidoU2F => Self::FIDO_U2F_FORMAT_CSTR,
        }
    }
}

impl FromStr for CredentialFormat {
    type Err = InvalidCredentialFormatError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            CredentialFormat::FIDO2_FORMAT => Ok(CredentialFormat::Fido2),
            CredentialFormat::FIDO_U2F_FORMAT => Ok(CredentialFormat::FidoU2F),
            _ => Err(InvalidCredentialFormatError),
        }
    }
}

#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    RS256 = COSE_RS256,
    ES256 = COSE_ES256,
    EDDSA = COSE_EDDSA,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InvalidCredentialFormatError;

impl error::Error for InvalidCredentialFormatError {}

impl fmt::Display for InvalidCredentialFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The credential string is invalid")
    }
}
