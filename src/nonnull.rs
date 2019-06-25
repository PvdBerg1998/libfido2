use std::cmp::{Eq, PartialEq};

/// Alternative to `std::ptr::NonNull`, with separate getter methods for `*const` and `*mut`,
/// requiring `&self` and `&mut self` respectively.
pub struct NonNull<T: ?Sized>(std::ptr::NonNull<T>);

impl<T: ?Sized> NonNull<T> {
    pub fn new(ptr: *mut T) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            unsafe { Some(NonNull(std::ptr::NonNull::new_unchecked(ptr))) }
        }
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
