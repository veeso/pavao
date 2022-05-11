//! # Utils
//!
//! utilities module

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

#[inline(always)]
/// Ok(ptr) for non-null ptr or Err(last_os_error) otherwise
pub fn result_from_ptr<T>(ptr: *const T) -> io::Result<*const T> {
    if ptr.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

pub unsafe fn cstr<'a, T>(p: *const T) -> Cow<'a, str> {
    CStr::from_ptr(p as *const c_char).to_string_lossy()
}

pub fn cstring<P: AsRef<str>>(p: P) -> SmbResult<CString> {
    Ok(CString::new(p.as_ref())?)
}

pub unsafe fn write_to_cstr(dest: *mut u8, len: usize, src: &str) {
    // just to ensure that it can be interpreted as c string
    *(dest.offset((len - 1) as isize)) = 0u8;
    trace!(target: "smbc", "orig: {:?}", cstr(dest));

    let mut buf = slice::from_raw_parts_mut(dest, len);
    let mut idx = buf.write(src.as_bytes()).unwrap();

    if idx == len {
        idx -= 1;
    }
    buf = slice::from_raw_parts_mut(dest, len);
    buf[idx] = 0u8;

    trace!(target: "smbc", "write to [{:p};{}] from [{:p},{}]: {:?}", dest, len, src.as_ptr(), src.len(), cstr(dest));
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
