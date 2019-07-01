use crate::{device::DevicePath, ffi::NonNull};
use libfido2_sys::*;
use std::{ffi::CStr, str};

/// Owns a list of [information] about found devices.
///
/// [information]: struct.DeviceInformation.html
#[derive(PartialEq, Eq)]
pub struct DeviceList {
    pub(crate) raw: NonNull<fido_dev_info>,
    // Length of allocation (may contain uninitialized memory)
    pub(crate) length: usize,
    // Length of found devices
    pub(crate) found: usize,
}

/// Information about a found, not connected to, device.
/// Contains OS-specific path, which can be used to connect to a device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceInformation<'a> {
    pub path: DevicePath<'a>,
    pub product_id: i16,
    pub vendor_id: i16,
    pub manufacturer: &'a str,
    pub product: &'a str,
}

impl DeviceList {
    /// Creates an iterator over [information] about found devices.
    ///
    /// [information]: struct.DeviceInformation.html
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = DeviceInformation<'a>> {
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
            let manufacturer = str::from_utf8_unchecked(CStr::from_ptr(manufacturer).to_bytes());

            let product = fido_dev_info_product_string(device_info);
            assert!(!product.is_null());
            let product = str::from_utf8_unchecked(CStr::from_ptr(product).to_bytes());

            DeviceInformation {
                path,
                product_id,
                vendor_id,
                manufacturer,
                product,
            }
        })
    }

    /// Returns the amount of devices found.
    pub fn len(&self) -> usize {
        self.found
    }

    /// Returns whether there were no devices found.
    pub fn is_empty(&self) -> bool {
        self.found == 0
    }
}

// libfido2_sys guarantees this.
unsafe impl Send for DeviceList {}
unsafe impl Sync for DeviceList {}

impl Drop for DeviceList {
    fn drop(&mut self) {
        unsafe {
            let mut device_list = self.raw.as_ptr_mut();
            fido_dev_info_free(&mut device_list as *mut _, self.length);
            assert!(device_list.is_null());
        }
    }
}
