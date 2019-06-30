use crate::{ffi::NonNull, FidoError, Result, FIDO_OK};
use bitflags::bitflags;
use libfido2_sys::*;
use std::{ffi::CStr, slice};

// Raw assertion is initialized with NULL data
// Only expose this type when it is properly initialized (returned from device)
pub struct Assertion {
    pub(crate) raw: NonNull<fido_assert>,
}

// Wrapper type to safely initialize the assertion with enough information to pass to a device
pub struct AssertionCreator(Assertion);

/// Required information to verify an [`Assertion`] from a `Device`.
///
/// [`Assertion`]: struct.Assertion.html
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AssertionCreationData<'a> {
    pub relying_party_id: &'a CStr,
    pub client_data_hash: &'a [u8],
    pub allowed_credential_ids: Option<&'a [&'a [u8]]>,
    pub options: AssertionOptions,
}

impl<'a> AssertionCreationData<'a> {
    /// Constructs a new `AssertionCreationData` with given parameters and defaults.
    pub fn with_defaults(relying_party_id: &'a CStr, client_data_hash: &'a [u8]) -> Self {
        AssertionCreationData {
            relying_party_id,
            client_data_hash,
            allowed_credential_ids: None,
            options: AssertionOptions::empty(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    pub auth_data: &'a [u8],
    pub client_data_hash: &'a [u8],
    pub hmac_secret: Option<&'a [u8]>,
    pub signature: &'a [u8],
    pub user_id: Option<&'a [u8]>,
    pub user_name: Option<&'a CStr>,
    pub user_display_name: Option<&'a CStr>,
    pub user_image_uri: Option<&'a CStr>,
}

impl AssertionCreator {
    /// Makes sure the contained assertion is initialized for transfer to a device
    pub(crate) fn new(mut assertion: Assertion, data: AssertionCreationData<'_>) -> Result<Self> {
        // @TODO propagate location of error
        assertion.set_relying_party_id(data.relying_party_id)?;
        assertion.set_client_data_hash(data.client_data_hash)?;
        if let Some(allowed) = data.allowed_credential_ids {
            for allowed in allowed {
                assertion.add_allowed_credential_id(allowed)?;
            }
        }
        assertion.set_options(data.options)?;
        Ok(AssertionCreator(assertion))
    }

    pub(crate) fn raw(&self) -> &NonNull<fido_assert> {
        &self.0.raw
    }

    pub(crate) fn raw_mut(&mut self) -> &mut NonNull<fido_assert> {
        &mut self.0.raw
    }

    /// NB. Only call this after the assertion was returned from a device, or it will cause panics
    pub(crate) fn into_inner(self) -> Assertion {
        self.0
    }
}

impl Assertion {
    /// Creates an iterator over the [statements] contained in this assertion.
    ///
    /// [statements]: struct.Statement.html
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = Statement<'a>> {
        let assertion = self.raw.as_ptr();
        let client_data_hash = unsafe {
            fido_assert_clientdata_hash_ptr(assertion)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_assert_clientdata_hash_len(assertion)))
                .unwrap()
        };

        (0..self.len()).map(move |i| unsafe {
            let auth_data = fido_assert_authdata_ptr(assertion, i)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_assert_authdata_len(assertion, i)))
                .unwrap();

            let hmac_secret = fido_assert_hmac_secret_ptr(assertion, i)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_assert_hmac_secret_len(assertion, i)));

            let signature = fido_assert_sig_ptr(assertion, i)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_assert_sig_len(assertion, i)))
                .unwrap();

            let user_id = fido_assert_user_id_ptr(assertion, i)
                .as_ref()
                .map(|ptr| slice::from_raw_parts(ptr, fido_assert_user_id_len(assertion, i)));

            let user_name = fido_assert_user_name(assertion, i)
                .as_ref()
                .map(|ptr| CStr::from_ptr(ptr));

            let user_display_name = fido_assert_user_display_name(assertion, i)
                .as_ref()
                .map(|ptr| CStr::from_ptr(ptr));

            let user_image_uri = fido_assert_user_icon(assertion, i)
                .as_ref()
                .map(|ptr| CStr::from_ptr(ptr));

            Statement {
                auth_data,
                client_data_hash,
                hmac_secret,
                signature,
                user_id,
                user_name,
                user_display_name,
                user_image_uri,
            }
        })
    }

    /// Returns an iterator over the successfully verified [statements] contained in this assertion.
    ///
    /// [statements]: struct.Statement.html
    pub fn iter_verified<'a>(
        &'a self,
        public_key: PublicKey,
    ) -> impl Iterator<Item = Statement<'a>> {
        let assertion = self.raw.as_ptr();
        self.iter()
            .enumerate()
            .filter(move |(i, statement)| {
                unsafe {
                    //match fido_assert_verify(assertion, i, arg3: ::std::os::raw::c_int, arg4: *const ::std::os::raw::c_void)
                    false
                }
            })
            .map(|(_, statement)| statement)
    }

    /// Returns the amount of statements in this assertion.
    pub fn len(&self) -> usize {
        unsafe { fido_assert_count(self.raw.as_ptr()) }
    }

    /*
        Private FFI setters
    */

    fn set_count(&mut self, n: usize) -> Result<()> {
        unsafe {
            match fido_assert_set_count(self.raw.as_ptr_mut(), n) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_auth_data(&mut self, auth_data: &[u8], idx: usize) -> Result<()> {
        unsafe {
            match fido_assert_set_authdata(
                self.raw.as_ptr_mut(),
                idx,
                auth_data as *const _ as *const _,
                auth_data.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_signature(&mut self, signature: &[u8], idx: usize) -> Result<()> {
        unsafe {
            match fido_assert_set_sig(
                self.raw.as_ptr_mut(),
                idx,
                signature as *const _ as *const _,
                signature.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_relying_party_id(&mut self, relying_party_id: &CStr) -> Result<()> {
        unsafe {
            match fido_assert_set_rp(self.raw.as_ptr_mut(), relying_party_id.as_ptr()) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_options(&mut self, options: AssertionOptions) -> Result<()> {
        unsafe {
            match fido_assert_set_options(
                self.raw.as_ptr_mut(),
                options.contains(AssertionOptions::USER_PRESENCE),
                options.contains(AssertionOptions::USER_VERIFICATION),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_hmac_salt(&mut self, hmac_salt: &[u8]) -> Result<()> {
        unsafe {
            match fido_assert_set_hmac_salt(
                self.raw.as_ptr_mut(),
                hmac_salt as *const _ as *const _,
                hmac_salt.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn set_client_data_hash(&mut self, client_data_hash: &[u8]) -> Result<()> {
        unsafe {
            match fido_assert_set_clientdata_hash(
                self.raw.as_ptr_mut(),
                client_data_hash as *const _ as *const _,
                client_data_hash.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }

    fn add_allowed_credential_id(&mut self, id: &[u8]) -> Result<()> {
        unsafe {
            match fido_assert_allow_cred(
                self.raw.as_ptr_mut(),
                id as *const _ as *const _,
                id.len(),
            ) {
                FIDO_OK => Ok(()),
                err => Err(FidoError(err)),
            }
        }
    }
}

// libfido2_sys guarantees this.
unsafe impl Send for Assertion {}
unsafe impl Sync for Assertion {}

impl Drop for Assertion {
    fn drop(&mut self) {
        unsafe {
            let mut assertion = self.raw.as_ptr_mut();
            fido_assert_free(&mut assertion as *mut _);
            assert!(assertion.is_null());
        }
    }
}

// @TODO
pub enum PublicKey {}

bitflags! {
    /// Option flags for an [`Assertion`].
    ///
    /// [`Assertion`]: struct.Assertion.html
    pub struct AssertionOptions: u8 {
        /// Instructs the authenticator to require user consent to complete the operation.
        const USER_PRESENCE = 1;
        /// Instructs the authenticator to require a gesture that verifies the user to complete the request.
        const USER_VERIFICATION = 2;
    }
}
