use libfido2_sys::*;
use std::ptr::NonNull;

#[derive(Debug, PartialEq, Eq)]
pub struct Device {
    pub(crate) raw: NonNull<fido_dev>,
}

unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Drop for Device {
    fn drop(&mut self) {
        let mut device = self.raw.as_ptr();
        unsafe {
            // This can return an error
            let _ = fido_dev_close(device);
            fido_dev_free(&mut device as *mut _);
        }
        assert!(device.is_null(), "Device was not freed");
    }
}
