use crate::device::DevicePath;
use libfido2_sys::*;
use std::{ffi::CStr, ptr::NonNull};

#[derive(PartialEq, Eq)]
pub struct DeviceList {
    pub(crate) raw: NonNull<fido_dev_info>,
    pub(crate) length: usize,
    pub(crate) found: usize,
}

impl DeviceList {
    pub fn iter_info<'a>(&'a self) -> impl Iterator<Item = DeviceInformation<'a>> {
        let device_list = self.raw.as_ptr();
        (0..self.found).map(move |i| unsafe {
            // Obtain pointer to entry in list (0 based)
            let device_info = fido_dev_info_ptr(device_list, i);
            assert!(!device_info.is_null());

            // Acquire information from this entry
            let path = fido_dev_info_path(device_info);
            assert!(!path.is_null());
            let path = DevicePath(CStr::from_ptr(path));

            let product_id = fido_dev_info_product(device_info);
            let vendor_id = fido_dev_info_vendor(device_info);

            let manufacturer = fido_dev_info_manufacturer_string(device_info);
            assert!(!manufacturer.is_null());
            let manufacturer = CStr::from_ptr(manufacturer).to_str().unwrap();

            let product = fido_dev_info_product_string(device_info);
            assert!(!product.is_null());
            let product = CStr::from_ptr(product).to_str().unwrap();

            DeviceInformation {
                path,
                product_id,
                vendor_id,
                manufacturer,
                product,
            }
        })
    }
}

unsafe impl Send for DeviceList {}
unsafe impl Sync for DeviceList {}

impl Drop for DeviceList {
    fn drop(&mut self) {
        unsafe {
            let mut device_list = self.raw.as_ptr();
            fido_dev_info_free(&mut device_list as *mut _, self.length);
            assert!(device_list.is_null());
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceInformation<'a> {
    pub path: DevicePath<'a>,
    pub product_id: i16,
    pub vendor_id: i16,
    pub manufacturer: &'a str,
    pub product: &'a str,
}
