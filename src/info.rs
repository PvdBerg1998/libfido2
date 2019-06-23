use libfido2_sys::*;
use std::{ffi::CStr, ptr::NonNull};

#[derive(Debug, PartialEq, Eq)]
pub struct DeviceList {
    pub(crate) raw: NonNull<fido_dev_info>,
    pub(crate) length: usize,
    pub(crate) found: usize,
}

impl DeviceList {
    pub fn iter_info<'a>(&'a self) -> impl Iterator<Item = ProductInformation<'a>> {
        let device_list = self.raw.as_ptr();
        (0..self.found).map(move |i| unsafe {
            let device_info = fido_dev_info_ptr(device_list, i);
            assert!(!device_info.is_null());

            let path = fido_dev_info_path(device_info);
            assert!(!path.is_null());
            let path = CStr::from_ptr(path);

            let product_id = fido_dev_info_product(device_info);
            let vendor_id = fido_dev_info_vendor(device_info);

            let manufacturer = fido_dev_info_manufacturer_string(device_info);
            assert!(!manufacturer.is_null());
            let manufacturer = CStr::from_ptr(manufacturer);

            let product = fido_dev_info_product_string(device_info);
            assert!(!product.is_null());
            let product = CStr::from_ptr(product);

            ProductInformation {
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
        let mut device_list = self.raw.as_ptr();
        unsafe {
            fido_dev_info_free(&mut device_list as *mut _, self.length);
        }
        assert!(device_list.is_null(), "DeviceList was not freed");
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProductInformation<'a> {
    pub path: &'a CStr,
    pub product_id: i16,
    pub vendor_id: i16,
    pub manufacturer: &'a CStr,
    pub product: &'a CStr,
}
