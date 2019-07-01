use std::{
    cmp::{Eq, PartialEq},
    ffi::CStr,
    os::raw::c_char,
    slice, str,
};

/// Converts a `*const *mut c_char` to a boxed array of `&str`s.
///
/// # Unsafety
/// - Contained strings must be valid UTF-8.
pub(crate) unsafe fn convert_cstr_array_ptr<'a>(
    array: *const *mut c_char,
    len: usize,
) -> Box<[&'a str]> {
    slice::from_raw_parts(array, len)
        .iter()
        .map(|ptr| {
            assert!(!ptr.is_null());
            str::from_utf8_unchecked(CStr::from_ptr(*ptr).to_bytes())
        })
        .collect::<Vec<&'a str>>()
        .into_boxed_slice()
}

/// Alternative to `std::ptr::NonNull`, with separate getter methods for `*const` and `*mut`,
/// requiring `&self` and `&mut self` respectively.
pub struct NonNull<T: ?Sized>(std::ptr::NonNull<T>);

impl<T: ?Sized> NonNull<T> {
    pub fn new(ptr: *mut T) -> Option<Self> {
        std::ptr::NonNull::new(ptr).map(NonNull)
    }

    pub fn as_ptr(&self) -> *const T {
        self.0.as_ptr() as *const _
    }

    pub fn as_ptr_mut(&mut self) -> *mut T {
        self.0.as_ptr()
    }
}

impl<T: ?Sized> PartialEq for NonNull<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<T: ?Sized> Eq for NonNull<T> {}
