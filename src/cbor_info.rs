use libfido2_sys::*;
use std::ptr::NonNull;

#[derive(PartialEq, Eq)]
pub struct CBORInformation {
    pub(crate) raw: NonNull<fido_cbor_info>,
}

impl Drop for CBORInformation {
    fn drop(&mut self) {
        unsafe {
            let mut cbor_info = self.raw.as_ptr();
            fido_cbor_info_free(&mut cbor_info as *mut _);
            assert!(cbor_info.is_null());
        }
    }
}
