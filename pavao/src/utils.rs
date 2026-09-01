//! Conversions between native SMB values and safe Rust values.

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::slice;

use libc::{c_char, c_int};

use super::SmbResult;
use crate::SmbError;

#[inline(always)]
/// Returns `ptr` when non-null, or the last operating-system error otherwise.
///
/// # Errors
///
/// Returns the current operating-system error when `ptr` is null.
pub fn result_from_ptr_mut<T>(ptr: *mut T) -> io::Result<*mut T> {
    if ptr.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

/// Returns a const pointer when non-null, or the last operating-system error otherwise.
///
/// # Errors
///
/// Returns the current operating-system error when `ptr` is null.
pub fn result_from_ptr<T>(ptr: *const T) -> io::Result<*const T> {
    if ptr.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

/// Reads a borrowed C string, replacing invalid UTF-8 sequences.
///
/// # Safety
///
/// `p` must point to a valid NUL-terminated byte sequence that remains alive for `'a`.
pub unsafe fn cstr<'a, T>(p: *const T) -> Cow<'a, str> {
    unsafe { CStr::from_ptr(p as *const c_char).to_string_lossy() }
}

/// Writes `src` to a fixed-size C string buffer.
///
/// The source is truncated when it does not fit, preserving the terminating NUL byte.
///
/// # Safety
///
/// `dest` must be valid for writes of `len` bytes, and `len` must be greater than zero.
pub unsafe fn write_to_cstr(dest: *mut u8, len: usize, src: &str) {
    // just to ensure that it can be interpreted as c string
    unsafe {
        *dest.add(len - 1) = 0u8;
        trace!("orig: {value:?}", value = cstr(dest));

        let mut buf = slice::from_raw_parts_mut(dest, len);
        let mut idx = buf.write(src.as_bytes()).unwrap();

        if idx == len {
            idx -= 1;
        }
        buf = slice::from_raw_parts_mut(dest, len);
        buf[idx] = 0u8;

        trace!(
            "write to [{dest:p};{len}] from [{src_ptr:p},{src_len}]: {value:?}",
            src_ptr = src.as_ptr(),
            src_len = src.len(),
            value = cstr(dest)
        );
    }
}

/// Returns the last operating-system error as an [`SmbError`].
#[inline(always)]
pub fn last_os_error() -> SmbError {
    SmbError::Io(io::Error::last_os_error())
}

/// Returns `ok_val` unless an SMB function returned its `-1` failure sentinel.
///
/// # Errors
///
/// Returns the last operating-system error when `ret_val` equals `-1`.
#[inline(always)]
pub fn to_result_with_ioerror<T, U>(ok_val: T, ret_val: U) -> SmbResult<T>
where
    U: Eq + From<i8>,
{
    if ret_val == U::from(-1) {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ok_val)
    }
}

#[inline(always)]
/// Returns `t` unless it is the `-1` failure sentinel.
///
/// # Errors
///
/// Returns the last operating-system error when `t` equals `-1`.
pub fn to_result_with_le<T>(t: T) -> io::Result<T>
where
    T: Eq + From<i8>,
{
    to_result_with_error(t, io::Error::last_os_error())
}

#[inline(always)]
/// Returns `t` unless it is `-1`, using `errno` for the failure.
///
/// # Errors
///
/// Returns the error represented by `errno` when `t` equals `-1`.
pub fn to_result_with_errno<T>(t: T, errno: c_int) -> io::Result<T>
where
    T: Eq + From<i8>,
{
    to_result_with_error(t, io::Error::from_raw_os_error(errno))
}

#[inline(always)]
fn to_result_with_error<T>(t: T, err: io::Error) -> io::Result<T>
where
    T: Eq + From<i8>,
{
    if t == T::from(-1) { Err(err) } else { Ok(t) }
}

/// Converts a Rust string to a [`CString`].
///
/// # Errors
///
/// Returns [`SmbError::NulInPath`] if the string contains an interior NUL byte.
#[inline(always)]
pub fn str_to_cstring<P: AsRef<str>>(p: P) -> SmbResult<CString> {
    Ok(CString::new(p.as_ref())?)
}

/// Copies a NUL-terminated C string into a Rust [`String`].
///
/// # Errors
///
/// Returns [`SmbError::BadValue`] if `ptr` is null or the string is not valid UTF-8.
///
/// # Safety
///
/// Although this function is safe to call, `ptr` must reference a readable NUL-terminated string.
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
    use std::ptr;

    use pretty_assertions::assert_eq;

    use super::*;

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

    #[test]
    fn should_reject_null_char_pointer() {
        assert_eq!(
            char_ptr_to_string(ptr::null()).unwrap_err(),
            SmbError::BadValue
        );
    }

    #[test]
    fn should_reject_non_utf8_char_pointer() {
        let invalid_utf8 = [0xff_u8, 0];
        assert_eq!(
            char_ptr_to_string(invalid_utf8.as_ptr().cast()).unwrap_err(),
            SmbError::BadValue
        );
    }

    #[test]
    fn should_validate_pointer_results() {
        let mut value = 42_u8;
        let pointer = ptr::from_mut(&mut value);
        assert_eq!(result_from_ptr_mut(pointer).unwrap(), pointer);
        assert!(result_from_ptr_mut::<u8>(ptr::null_mut()).is_err());

        let const_pointer = ptr::from_ref(&value);
        assert_eq!(result_from_ptr(const_pointer).unwrap(), const_pointer);
        assert!(result_from_ptr::<u8>(ptr::null()).is_err());
    }

    #[test]
    fn should_write_truncated_c_strings() {
        let mut buffer = [0_u8; 5];

        // SAFETY: `buffer` is writable for the supplied non-zero length.
        unsafe { write_to_cstr(buffer.as_mut_ptr(), buffer.len(), "abcdef") };
        // SAFETY: `write_to_cstr` guarantees that the buffer is NUL-terminated.
        let actual = unsafe { cstr(buffer.as_ptr()) };

        assert_eq!(actual, "abcd");
    }

    #[test]
    fn should_preserve_successful_smb_return_values() {
        assert_eq!(to_result_with_ioerror(42, 0_i32).unwrap(), 42);
        assert_eq!(to_result_with_le(42_i32).unwrap(), 42);
        assert_eq!(to_result_with_errno(42_i32, libc::EINVAL).unwrap(), 42);
    }

    #[test]
    fn should_convert_failed_smb_return_values() {
        assert!(to_result_with_ioerror(42, -1_i32).is_err());
        assert!(to_result_with_le(-1_i32).is_err());
        assert_eq!(
            to_result_with_errno(-1_i32, libc::EINVAL)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn should_return_last_os_error_as_io_error() {
        assert!(matches!(last_os_error(), SmbError::Io(_)));
    }

    #[test]
    fn should_reject_strings_containing_nul() {
        assert!(matches!(
            str_to_cstring("nul\0path"),
            Err(SmbError::NulInPath(_))
        ));
    }
}
