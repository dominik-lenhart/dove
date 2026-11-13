//! Windows security primitives: the current user's SID, private DACLs, the strict-permission check, DPAPI and the
//! identity of a named pipe's peer (spec 6.4, PLAN A58). Every unsafe block is a plain Win32 call; buffers the system
//! allocates are released by RAII guards.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid,
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenElevation, TokenOwner, TokenUser,
    WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// ACE types (winnt.h). Only the plain allowed/denied types are understood; any other ACE makes a path non-private.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// A copied SID (the bytes of a `SID` structure).
#[derive(Clone, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Copies the SID at `p`.
    ///
    /// # Safety
    /// `p` must point to a valid SID.
    unsafe fn copy_from(p: PSID) -> io::Result<Self> {
        if p.is_null() || unsafe { IsValidSid(p) } == 0 {
            return Err(io::Error::other("invalid SID"));
        }
        let len = unsafe { GetLengthSid(p) } as usize;
        Ok(Self(unsafe { std::slice::from_raw_parts(p as *const u8, len) }.to_vec()))
    }

    fn as_psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }

    /// The string form, for example `S-1-5-21-...`.
    pub fn to_string_sid(&self) -> io::Result<String> {
        let mut out: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut out) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _free = Local(out as *mut c_void);
        let mut len = 0;
        while unsafe { *out.add(len) } != 0 {
            len += 1;
        }
        Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) }))
    }

    fn equals(&self, other: PSID) -> bool {
        unsafe { EqualSid(self.as_psid(), other) != 0 }
    }
}

impl std::fmt::Debug for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_sid().unwrap_or_else(|_| "<invalid sid>".into()))
    }
}

/// Memory returned by the system that must be released with `LocalFree`.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 elements keep the buffer aligned for the pointer-carrying structures it holds.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    if unsafe { GetTokenInformation(token.0, class, buf.as_mut_ptr() as *mut c_void, len, &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

fn token_user(token: &Handle) -> io::Result<Sid> {
    let buf = token_info(token, TokenUser)?;
    // TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the SID pointer (into `buf`).
    let sid = unsafe { *(buf.as_ptr() as *const PSID) };
    unsafe { Sid::copy_from(sid) }
}

fn token_owner(token: &Handle) -> io::Result<Sid> {
    let buf = token_info(token, TokenOwner)?;
    let sid = unsafe { *(buf.as_ptr() as *const PSID) };
    unsafe { Sid::copy_from(sid) }
}

fn own_token() -> io::Result<Handle> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(token))
}

/// The SID of the user this process runs as.
pub fn current_user_sid() -> io::Result<Sid> {
    token_user(&own_token()?)
}

/// Whether this process runs elevated (an administrator token).
pub fn is_elevated() -> bool {
    let Ok(token) = own_token() else { return false };
    match token_info(&token, TokenElevation) {
        Ok(buf) => unsafe { (*(buf.as_ptr() as *const TOKEN_ELEVATION)).TokenIsElevated != 0 },
        Err(_) => false,
    }
}

/// The user SID of process `pid`.
pub fn process_user_sid(pid: u32) -> io::Result<Sid> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = Handle(process);
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    token_user(&Handle(token))
}

/// The user SID of the process at the other end of a connected named pipe server handle (the admin channel's peer
/// check, the twin of `SO_PEERCRED`).
pub fn pipe_client_sid(pipe: RawHandle) -> io::Result<Sid> {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    process_user_sid(pid)
}

/// The user SID of the process that created the pipe a client handle is connected to. The CLI checks it before it
/// sends anything, so a pipe squatted by another user never receives a request (a password, for example).
pub fn pipe_server_sid(pipe: RawHandle) -> io::Result<Sid> {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    process_user_sid(pid)
}

/// A self-relative security descriptor built from SDDL.
pub struct SecurityDescriptor {
    sd: Local,
}

// SAFETY: the descriptor is an owned, immutable heap block (LocalAlloc); nothing else holds the pointer.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let w = wide(OsStr::new(sddl));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { sd: Local(sd) })
    }

    /// Owner = `user`, protected DACL with full control for `user` only (inherited by files and subdirectories when
    /// `container`).
    pub fn private_to(user: &Sid, container: bool) -> io::Result<Self> {
        let s = user.to_string_sid()?;
        let inherit = if container { "OICI" } else { "" };
        Self::from_sddl(&format!("O:{s}D:P(A;{inherit};FA;;;{s})"))
    }

    /// Security attributes pointing at this descriptor; valid while `self` lives.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: 0,
        }
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(self.sd.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other("security descriptor has no DACL"));
        }
        Ok(dacl)
    }
}

/// Makes `path` private to the current user: owner = user, protected DACL with full control for the user only
/// (inheritable for directories). Replaces whatever DACL the path had.
pub fn restrict(path: &Path, container: bool) -> io::Result<()> {
    let user = current_user_sid()?;
    let sd = SecurityDescriptor::private_to(&user, container)?;
    let dacl = sd.dacl()?;
    let w = wide(path.as_os_str());
    let rc = unsafe {
        SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            user.as_psid(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Creates one directory with a private DACL (fails if it exists).
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let user = current_user_sid()?;
    let sd = SecurityDescriptor::private_to(&user, true)?;
    let sa = sd.attributes();
    let w = wide(path.as_os_str());
    if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Why a path is not private, or `Ok(())`. Private means: the owner is the current user (or the default owner of
/// this process's objects, `BUILTIN\Administrators` for an elevated administrator), and every allow entry of the DACL
/// is for the current user, `SYSTEM`, `BUILTIN\Administrators` or `CREATOR OWNER`. Everyone, Users, Authenticated
/// Users and any other account make it non-private, and so does a missing (NULL) DACL, which grants everyone
/// everything. Deny entries never widen access and are ignored.
pub fn check_private(path: &Path) -> Result<(), String> {
    let user = current_user_sid().map_err(|e| format!("cannot read the current user: {e}"))?;
    let default_owner = own_token().and_then(|t| token_owner(&t)).ok();
    let w = wide(path.as_os_str());
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("cannot read its permissions: {}", io::Error::from_raw_os_error(rc as i32)));
    }
    let _free = Local(sd);
    if owner.is_null() || !(user.equals(owner) || default_owner.as_ref().is_some_and(|o| o.equals(owner))) {
        return Err("it is not owned by the current user".into());
    }
    unsafe { check_dacl(dacl, &user) }
}

/// # Safety
/// `dacl` must be null or point to a valid ACL.
unsafe fn check_dacl(dacl: *mut ACL, user: &Sid) -> Result<(), String> {
    if dacl.is_null() {
        return Err("it has no access list (everyone has full access)".into());
    }
    let mut info = ACL_SIZE_INFORMATION { AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0 };
    if unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(format!("cannot read its access list: {}", io::Error::last_os_error()));
    }
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return Err(format!("cannot read its access list: {}", io::Error::last_os_error()));
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        match header.AceType {
            ACCESS_DENIED_ACE_TYPE => continue,
            ACCESS_ALLOWED_ACE_TYPE => {
                let sid = unsafe { &(*(ace as *const ACCESS_ALLOWED_ACE)).SidStart } as *const u32 as PSID;
                let trusted = user.equals(sid)
                    || [WinLocalSystemSid, WinBuiltinAdministratorsSid, WinCreatorOwnerSid]
                        .into_iter()
                        .any(|k| unsafe { IsWellKnownSid(sid, k) } != 0);
                if !trusted {
                    let other = unsafe { Sid::copy_from(sid) }.map(|s| format!("{s:?}")).unwrap_or_default();
                    return Err(format!("its access list grants access to another account ({other})"));
                }
            }
            t => return Err(format!("its access list has an entry of type {t} that Dove does not accept")),
        }
    }
    Ok(())
}

/// The allow entries of a kernel object's DACL (a named pipe, for example) as SID strings; `None` for a NULL DACL.
pub fn handle_allowed_sids(handle: RawHandle) -> io::Result<Option<Vec<String>>> {
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            handle as HANDLE,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _free = Local(sd);
    if dacl.is_null() {
        return Ok(None);
    }
    let mut info = ACL_SIZE_INFORMATION { AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0 };
    if unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { (*(ace as *const ACE_HEADER)).AceType } == ACCESS_ALLOWED_ACE_TYPE {
            let sid = unsafe { &(*(ace as *const ACCESS_ALLOWED_ACE)).SidStart } as *const u32 as PSID;
            out.push(unsafe { Sid::copy_from(sid) }?.to_string_sid()?);
        }
    }
    Ok(Some(out))
}

/// Encrypts `data` for the current Windows user (DPAPI, CurrentUser scope).
pub fn dpapi_protect(data: &[u8]) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    if unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(out.pbData as *mut c_void);
    Ok(unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec())
}

/// Decrypts a DPAPI blob of the current user. The system's plaintext copy is wiped before it is freed.
pub fn dpapi_unprotect(blob: &[u8]) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    if unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(out.pbData as *mut c_void);
    let plain = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
    let copy = zeroize::Zeroizing::new(plain.to_vec());
    zeroize::Zeroize::zeroize(plain);
    Ok(copy)
}

/// Replaces the DACL of `path` with the one in `sddl` (a `D:` string). Tests only.
#[cfg(test)]
pub(crate) fn set_dacl(path: &Path, sddl: &str) {
    let sd = SecurityDescriptor::from_sddl(sddl).unwrap();
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    assert_ne!(unsafe { GetSecurityDescriptorDacl(sd.sd.0, &mut present, &mut dacl, &mut defaulted) }, 0);
    let w = wide(path.as_os_str());
    let rc = unsafe {
        SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    assert_eq!(rc, ERROR_SUCCESS, "SetNamedSecurityInfoW");
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn me() -> String {
        current_user_sid().unwrap().to_string_sid().unwrap()
    }

    /// Adds an Everyone:read entry next to the current user's (the Windows twin of a 0644 file).
    pub(crate) fn grant_everyone_read(path: &Path) {
        set_dacl(path, &format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", me()));
    }

    #[test]
    fn current_user_sid_is_a_user_sid() {
        let s = me();
        assert!(s.starts_with("S-1-5-"), "{s}");
        assert_eq!(current_user_sid().unwrap(), current_user_sid().unwrap());
        assert_eq!(process_user_sid(std::process::id()).unwrap(), current_user_sid().unwrap());
    }

    #[test]
    fn only_private_paths_pass_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kek");
        std::fs::write(&p, "x").unwrap();
        restrict(&p, false).unwrap();
        check_private(&p).unwrap();
        let me = me();
        for (sddl, why) in [
            (format!("D:P(A;;FA;;;{me})(A;;FR;;;WD)"), "another account"),
            (format!("D:P(A;;FA;;;{me})(A;;FR;;;BU)"), "another account"),
            (format!("D:P(A;;FA;;;{me})(A;;FR;;;AU)"), "another account"),
            ("D:NO_ACCESS_CONTROL".to_string(), "no access list"),
        ] {
            set_dacl(&p, &sddl);
            let err = check_private(&p).unwrap_err();
            assert!(err.contains(why), "{sddl}: {err}");
        }
        // SYSTEM, Administrators and deny entries do not make a file public.
        set_dacl(&p, &format!("D:P(A;;FA;;;{me})(A;;FA;;;SY)(A;;FA;;;BA)(D;;FA;;;WD)"));
        check_private(&p).unwrap();
    }

    #[test]
    fn private_directories_pass_and_their_files_inherit() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("data");
        create_private_dir(&d).unwrap();
        check_private(&d).unwrap();
        let f = d.join("state.db");
        std::fs::write(&f, "x").unwrap();
        check_private(&f).unwrap();
    }

    #[test]
    fn dpapi_round_trip() {
        let blob = dpapi_protect(b"secret key line").unwrap();
        assert!(!blob.windows(6).any(|w| w == b"secret"));
        assert_eq!(&**dpapi_unprotect(&blob).unwrap(), b"secret key line");
        let mut broken = blob.clone();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        assert!(dpapi_unprotect(&broken).is_err());
    }
}
