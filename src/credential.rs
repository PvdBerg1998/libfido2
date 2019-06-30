use crate::{ffi::NonNull, FidoError, Result, FIDO_OK};
use bitflags::bitflags;
use libfido2_sys::*;
use std::{error, ffi::CStr, fmt, os::raw, ptr, slice, str::FromStr};

// Raw Credential is initialized with NULL data
// Only expose this type when it is properly initialized (returned from device)
pub struct Credential {
    pub(crate) raw: NonNull<fido_cred>,
}

// Wrapper type to safely initialize the Credential with enough information to pass to a device
pub struct CredentialCreator(Credential);

/// Required information to request a new [`Credential`] from a `Device`.
///
/// [`Credential`]: struct.Credential.html
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CredentialCreationData<'a> {
    pub excluded_ids: &'a [u8],
    pub credential_type: CredentialType,
    pub client_data_hash: &'a [u8],
    pub relying_party_id: &'a CStr,
    pub relying_party_name: &'a CStr,
    pub user_id: &'a [u8],
    pub user_name: &'a CStr,
    pub user_display_name: Option<&'a CStr>,
    pub user_image_uri: Option<&'a CStr>,
    pub options: CredentialOptions,
    pub extensions: CredentialExtensions,
}

// Possible to retrieve after a Credential was returned from a device
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef<'a> {
    pub format: &'a CStr,
    pub auth_data: &'a [u8],
    pub client_data_hash: &'a [u8],
    pub id: &'a [u8],
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
    pub x509_certificate: &'a [u8],
}

impl<'a> CredentialCreationData<'a> {
    /// Constructs a new `CredentialCreationData` with given parameters and defaults.
    pub fn with_defaults(
        client_data_hash: &'a [u8],
        relying_party_id: &'a CStr,
        relying_party_name: &'a CStr,
        user_id: &'a [u8],
        user_name: &'a CStr,
    ) -> Self {
        CredentialCreationData {
            excluded_ids: &[],
            credential_type: CredentialType::ES256,
            client_data_hash,
            relying_party_id,
            relying_party_name,
            user_id,
            user_name,
            user_display_name: None,
            user_image_uri: None,
            options: CredentialOptions::empty(),
            extensions: CredentialExtensions::empty(),
        }
    }
}

impl CredentialCreator {
    /// Makes sure the contained Credential is initialized for transfer to a device
    pub(crate) fn new(
        mut credential: Credential,
        data: CredentialCreationData<'_>,
    ) -> Result<Self> {
        // @TODO propagate location of error
        // @FIXME calling this with len==0 results in FIDO_ERR_INTERNAL
        if !data.excluded_ids.is_empty() {
            credential.set_excluded(data.excluded_ids)?;
        }
        credential.set_type(data.credential_type)?;
        credential.set_client_data_hash(data.client_data_hash)?;
        credential.set_relying_party(data.relying_party_id, data.relying_party_name)?;
        credential.set_user(
            data.user_id,
            data.user_name,
            data.user_display_name,
            data.user_image_uri,
        )?;
        credential.set_options(data.options)?;
        credential.set_extensions(data.extensions)?;
        Ok(CredentialCreator(credential))
    }

    pub(crate) fn raw(&self) -> &NonNull<fido_cred> {
        &self.0.raw
    }

    pub(crate) fn raw_mut(&mut self) -> &mut NonNull<fido_cred> {
        &mut self.0.raw
    }

    /// NB. Only call this after the Credential was returned from a device, or it will cause panics
    pub(crate) fn into_inner(self) -> Credential {
        self.0
    }
}

impl Credential {
    pub fn as_ref<'a>(&'a self) -> CredentialRef<'a> {
        unsafe {
            let credential = self.raw.as_ptr();

            let format = fido_cred_fmt(credential)
                .as_ref()
                .map(|ptr| CStr::from_ptr(ptr))
                .unwrap();

            let auth_data = fido_cred_authdata_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_authdata_len(credential)))
                .unwrap();

            let client_data_hash = fido_cred_clientdata_hash_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_clientdata_hash_len(credential)))
                .unwrap();

            let id = fido_cred_id_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_id_len(credential)))
                .unwrap();

            let public_key = fido_cred_pubkey_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_pubkey_len(credential)))
                .unwrap();

            let signature = fido_cred_sig_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_sig_len(credential)))
                .unwrap();

            let x509_certificate = fido_cred_x5c_ptr(credential)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_cred_x5c_len(credential)))
                .unwrap();

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

    /// Verifies that the Credential was signed with the key attested in the x509 certificate.
    ///
    /// # Remarks
    /// - The x509 certificate itself is not verified
    pub fn verify(&self) -> Result<()> {
        unsafe {
            match fido_cred_verify(self.raw.as_ptr()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    /*
        Private FFI setters
    */

    fn set_excluded(&mut self, excluded_ids: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_exclude(
                self.raw.as_ptr_mut(),
                excluded_ids as *const _ as *const _,
                excluded_ids.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_type(&mut self, credential_type: CredentialType) -> Result<()> {
        unsafe {
            match fido_cred_set_type(self.raw.as_ptr_mut(), credential_type as raw::c_int) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_client_data_hash(&mut self, client_data_hash: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_clientdata_hash(
                self.raw.as_ptr_mut(),
                client_data_hash as *const _ as *const _,
                client_data_hash.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_relying_party(&mut self, id: &CStr, name: &CStr) -> Result<()> {
        unsafe {
            match fido_cred_set_rp(self.raw.as_ptr_mut(), id.as_ptr(), name.as_ptr()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_user(
        &mut self,
        id: &[u8],
        name: &CStr,
        display_name: Option<&CStr>,
        image_uri: Option<&CStr>,
    ) -> Result<()> {
        unsafe {
            match fido_cred_set_user(
                self.raw.as_ptr_mut(),
                id as *const _ as *const _,
                id.len(),
                name.as_ptr(),
                display_name.map(CStr::as_ptr).unwrap_or(ptr::null()),
                image_uri.map(CStr::as_ptr).unwrap_or(ptr::null()),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_format(&mut self, fmt: CredentialFormat) -> Result<()> {
        unsafe {
            match fido_cred_set_fmt(self.raw.as_ptr_mut(), fmt.to_ffi()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_auth_data(&mut self, auth_data: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_authdata(
                self.raw.as_ptr_mut(),
                auth_data as *const _ as *const _,
                auth_data.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_x509_certificate(&mut self, x509_certificate: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_x509(
                self.raw.as_ptr_mut(),
                x509_certificate as *const _ as *const _,
                x509_certificate.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        unsafe {
            match fido_cred_set_sig(
                self.raw.as_ptr_mut(),
                signature as *const _ as *const _,
                signature.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
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
    /// Extension flags for a [`Credential`].
    ///
    /// [`Credential`]: struct.Credential.html
    pub struct CredentialExtensions: raw::c_int {
        /// Enables the ability to generate a symmetric secret.
        const HMAC_SECRET = FIDO_EXT_HMAC_SECRET as raw::c_int;
    }
}

bitflags! {
    /// Option flags for a [`Credential`].
    ///
    /// [`Credential`]: struct.Credential.html
    pub struct CredentialOptions: u8 {
        /// Instructs the authenticator to store the key material on the device.
        const RESIDENT_KEY = 1;
        /// Instructs the authenticator to require a gesture that verifies the user to complete the request.
        const USER_VERIFICATION = 2;
    }
}

/// Possible data formats for a [`Credential`].
///
/// [`Credential`]: struct.Credential.html
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

/// Possible public key formats for a [`Credential`].
///
/// [`Credential`]: struct.Credential.html
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredentialType {
    ES256 = COSE_ES256,
    RS256 = COSE_RS256,
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
