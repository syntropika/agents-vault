//! Security.framework verification uses the kernel's connection audit token to
//! bind code identity to a particular process incarnation, avoiding PID reuse.

use std::{
    ffi::c_void,
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
    ptr,
};

type Cf = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataCreate(allocator: Cf, bytes: *const u8, length: isize) -> Cf;
    fn CFStringCreateWithBytes(
        allocator: Cf,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> Cf;
    fn CFDictionaryCreate(
        allocator: Cf,
        keys: *const Cf,
        values: *const Cf,
        count: isize,
        key_callbacks: Cf,
        value_callbacks: Cf,
    ) -> Cf;
    fn CFRelease(value: Cf);
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: Cf;
    fn SecCodeCopyGuestWithAttributes(host: Cf, attributes: Cf, flags: u32, guest: *mut Cf) -> i32;
    fn SecRequirementCreateWithString(text: Cf, flags: u32, requirement: *mut Cf) -> i32;
    fn SecCodeCheckValidity(code: Cf, flags: u32, requirement: Cf) -> i32;
}

struct Owned(Cf);
impl Owned {
    fn new(value: Cf) -> io::Result<Self> {
        if value.is_null() {
            return Err(io::Error::other("Security framework returned no object"));
        }
        Ok(Self(value))
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.0);
        }
    }
}

pub(super) fn authenticate(stream: &UnixStream, requirement: &str) -> io::Result<()> {
    // audit_token_t is eight uint32_t words in the macOS SDK. LOCAL_PEERTOKEN
    // is public in sys/un.h and returns the peer's token, not caller data.
    let mut token = [0_u32; 8];
    let mut size = std::mem::size_of_val(&token) as libc::socklen_t;
    unsafe {
        if libc::getsockopt(
            stream.as_raw_fd(),
            0,
            0x006,
            token.as_mut_ptr().cast(),
            &mut size,
        ) != 0
            || size as usize != std::mem::size_of_val(&token)
        {
            return Err(io::Error::last_os_error());
        }
        let token = Owned::new(CFDataCreate(
            ptr::null(),
            token.as_ptr().cast(),
            size as isize,
        ))?;
        let keys = [kSecGuestAttributeAudit];
        let values = [token.0];
        let attributes = Owned::new(CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        ))?;
        let mut code = ptr::null();
        check(SecCodeCopyGuestWithAttributes(
            ptr::null(),
            attributes.0,
            0,
            &mut code,
        ))?;
        let code = Owned::new(code)?;
        let text = Owned::new(CFStringCreateWithBytes(
            ptr::null(),
            requirement.as_ptr(),
            requirement.len() as isize,
            0x0800_0100,
            0,
        ))?;
        let mut requirement = ptr::null();
        check(SecRequirementCreateWithString(text.0, 0, &mut requirement))?;
        let requirement = Owned::new(requirement)?;
        check(SecCodeCheckValidity(code.0, 0, requirement.0))
    }
}

fn check(status: i32) -> io::Result<()> {
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer signature rejected ({status})"),
        ));
    }
    Ok(())
}
