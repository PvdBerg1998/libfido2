use crate::{ffi::NonNull, FidoError, Result};
use libfido2_sys::*;
use std::{ffi::CStr, slice};

pub struct Assertion {
    pub(crate) raw: NonNull<fido_assert>,
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

impl Assertion {
    /// Returns the amount of statements in this assertion.
    pub fn len(&self) -> usize {
        unsafe { fido_assert_count(self.raw.as_ptr()) }
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
