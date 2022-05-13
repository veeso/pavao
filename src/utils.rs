//! # Utils
//!
//! utilities module

use crate::SmbError;

use super::SmbResult;

use libc::{c_char, c_int};

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::slice;

#[inline(always)]
/// Ok(ptr) for non-null ptr or Err(last_os_error) otherwise
pub fn result_from_ptr_mut<T>(ptr: *mut T) -> io::Result<*mut T> {
    if ptr.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

pub unsafe fn cstr<'a, T>(p: *const T) -> Cow<'a, str> {
    CStr::from_ptr(p as *const c_char).to_string_lossy()
}

pub unsafe fn write_to_cstr(dest: *mut u8, len: usize, src: &str) {
    // just to ensure that it can be interpreted as c string
    *dest.add(len - 1) = 0u8;
    trace!("orig: {:?}", cstr(dest));

    let mut buf = slice::from_raw_parts_mut(dest, len);
    let mut idx = buf.write(src.as_bytes()).unwrap();

    if idx == len {
        idx -= 1;
    }
    buf = slice::from_raw_parts_mut(dest, len);
    buf[idx] = 0u8;

    trace!(
        "write to [{:p};{}] from [{:p},{}]: {:?}",
        dest,
        len,
        src.as_ptr(),
        src.len(),
        cstr(dest)
    );
}

/// Get last os error
#[inline(always)]
pub fn last_os_error() -> SmbError {
    SmbError::Io(io::Error::last_os_error())
}

/// Given the return value of a smb function, it returns the last OS error in case the ret_val is equal to -1
/// otherwise return `Ok(ok_val)`
#[inline(always)]
pub fn to_result_with_ioerror<T, U: Eq + From<i8>>(ok_val: T, ret_val: U) -> SmbResult<T> {
    if ret_val == U::from(-1) {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ok_val)
    }
}

#[inline(always)]
/// to io::Result with Err(last_os_error) if t == -1
pub fn to_result_with_le<T: Eq + From<i8>>(t: T) -> io::Result<T> {
    to_result_with_error(t, io::Error::last_os_error())
}

#[inline(always)]
/// to io::Result with Err(from_raw_os_error(errno)) if t == -1
pub fn to_result_with_errno<T: Eq + From<i8>>(t: T, errno: c_int) -> io::Result<T> {
    to_result_with_error(t, io::Error::from_raw_os_error(errno as i32))
}

#[inline(always)]
fn to_result_with_error<T: Eq + From<i8>>(t: T, err: io::Error) -> io::Result<T> {
    if t == T::from(-1) {
        Err(err)
    } else {
        Ok(t)
    }
}

/// Convert a string to a `CString`
#[inline(always)]
pub fn str_to_cstring<P: AsRef<str>>(p: P) -> SmbResult<CString> {
    Ok(CString::new(p.as_ref())?)
}

/// Convert char pointer to string
#[inline(always)]
pub fn char_ptr_to_string(ptr: *const c_char) -> SmbResult<String> {
    if ptr.is_null() {
        return Err(SmbError::BadValue);
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(ptr) };
    c_str
        .to_str()
        .map(|x| x.to_string())
        .map_err(|_| SmbError::BadValue)
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_convert_str_to_cstring() {
        assert!(str_to_cstring("Hello, World!").is_ok());
    }

    #[test]
    fn should_convert_char_ptr_to_string() {
        let c_str = std::ffi::CString::new("Hello, World!").unwrap();
        let ptr = c_str.as_ptr();
        assert_eq!(
            char_ptr_to_string(ptr).ok().unwrap().as_str(),
            "Hello, World!"
        );
    }
}
