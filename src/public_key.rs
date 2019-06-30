use crate::{ffi::NonNull, FidoError, Result, FIDO_OK};
use libfido2_sys::*;

pub enum PublicKey {
    ES256(ES256),
    RS256(RS256),
    EDDSA(EDDSA),
}

// @TODO add way to create this from <something else>. openssl maybe.
impl PublicKey {
    pub(crate) fn new_es256(data: &[u8]) -> Result<PublicKey> {
        unsafe {
            let mut pk = ES256(NonNull::new(es256_pk_new()).unwrap());
            match es256_pk_from_ptr(pk.0.as_ptr_mut(), data as *const _ as *const _, data.len()) {
                FIDO_OK => Ok(PublicKey::ES256(pk)),
                err => Err(FidoError(err)),
            }
        }
    }

    pub(crate) fn new_rs256(data: &[u8]) -> Result<PublicKey> {
        unsafe {
            let mut pk = RS256(NonNull::new(rs256_pk_new()).unwrap());
            match rs256_pk_from_ptr(pk.0.as_ptr_mut(), data as *const _ as *const _, data.len()) {
                FIDO_OK => Ok(PublicKey::RS256(pk)),
                err => Err(FidoError(err)),
            }
        }
    }

    pub(crate) fn new_eddsa(data: &[u8]) -> Result<PublicKey> {
        unsafe {
            let mut pk = EDDSA(NonNull::new(eddsa_pk_new()).unwrap());
            match eddsa_pk_from_ptr(pk.0.as_ptr_mut(), data as *const _ as *const _, data.len()) {
                FIDO_OK => Ok(PublicKey::EDDSA(pk)),
                err => Err(FidoError(err)),
            }
        }
    }
}

pub struct ES256(pub(crate) NonNull<es256_pk>);
pub struct RS256(pub(crate) NonNull<rs256_pk>);
pub struct EDDSA(pub(crate) NonNull<eddsa_pk>);

// libfido2_sys guarantees this.
unsafe impl Send for ES256 {}
unsafe impl Sync for ES256 {}
unsafe impl Send for RS256 {}
unsafe impl Sync for RS256 {}
unsafe impl Send for EDDSA {}
unsafe impl Sync for EDDSA {}

impl Drop for ES256 {
    fn drop(&mut self) {
        unsafe {
            let mut pk = self.0.as_ptr_mut();
            es256_pk_free(&mut pk as *mut _);
            assert!(pk.is_null());
        }
    }
}

impl Drop for RS256 {
    fn drop(&mut self) {
        unsafe {
            let mut pk = self.0.as_ptr_mut();
            rs256_pk_free(&mut pk as *mut _);
            assert!(pk.is_null());
        }
    }
}

impl Drop for EDDSA {
    fn drop(&mut self) {
        unsafe {
            let mut pk = self.0.as_ptr_mut();
            eddsa_pk_free(&mut pk as *mut _);
            assert!(pk.is_null());
        }
    }
}
