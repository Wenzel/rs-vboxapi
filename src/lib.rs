//! Minimal binding to VirtualBox's C API, loaded at runtime (dlopen) from an installed VirtualBox.
//!
//! It covers only what libmicrovmi's MachineDebugger access method needs: attach a shared
//! session to a running VM by name and read guest physical memory through `IMachineDebugger`.
//!
//! The function table and vtable indices are hand-written from `VBoxCAPI_v7_3.h`
//! (`sdk/bindings/c/include` of a VirtualBox build); `VBoxCAPIGlue.c` is the loader reference.

use std::ffi::c_void;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

use libloading::Library;

type HResult = u32;

// shortcut: Linux/XPCOM only (Windows uses VBoxCAPI.dll and IDispatch-based vtables), extend for Windows CI.
const LIB_NAME: &str = "VBoxXPCOMC.so";
/// Searched in order when `VBOX_APP_HOME` is not set, like `VBoxCGlueInit`.
const SEARCH_DIRS: &[&str] = &["/opt/VirtualBox", "/usr/lib/virtualbox"];

const CAPI_VERSION: u32 = 0x0004_0001;
const VBOX_E_OBJECT_NOT_FOUND: HResult = 0x80BB_0001;
const E_UNEXPECTED: HResult = 0x8000_FFFF;
const LOCK_TYPE_SHARED: u32 = 1;
/// `MachineState_FirstOnline..=MachineState_LastOnline`: states with a VM process to talk to.
const MACHINE_STATES_ONLINE: std::ops::RangeInclusive<u32> = 6..=19;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("VirtualBox C API library not found: {0} (set VBOX_APP_HOME to the VirtualBox install directory)")]
    LibraryNotFound(String),
    #[error("incompatible VirtualBox C API library: {0}")]
    LibraryIncompatible(String),
    #[error("VM {0:?} not found")]
    VmNotFound(String),
    #[error("VM {name:?} is not running (MachineState {state})")]
    VmNotRunning { name: String, state: u32 },
    #[error("VirtualBox API call {call} failed with {rc:#010x}{}", text.as_ref().map(|t| format!(": {}", t)).unwrap_or_default())]
    Api {
        call: &'static str,
        rc: u32,
        text: Option<String>,
    },
}

#[repr(C)]
struct NsId(u32, u16, u16, [u8; 8]);

const IID_IVIRTUALBOXERRORINFO: NsId = NsId(
    0xc1bc_c6d5,
    0x7966,
    0x481d,
    [0xab, 0x0b, 0xd0, 0xed, 0x73, 0xe2, 0x81, 0x35],
);

/// Prefix of `VBOXCAPI`, up to the last entry used. Unused entries are typed as `usize`.
#[repr(C)]
struct CApi {
    _cb: u32,
    version: u32,
    _get_versions: [usize; 2],
    client_initialize: unsafe extern "C" fn(*const c_char, *mut *mut Obj) -> HResult,
    _client_thread_init_uninit: [usize; 2],
    client_uninitialize: unsafe extern "C" fn(),
    _com_init_uninit: [usize; 2],
    /// Frees strings and raw XPCOM out-arrays (`pfnComUnallocMem` is an alias of it).
    com_unalloc_string: unsafe extern "C" fn(*mut c_void),
    _utf: [usize; 4],
    _safe_array: [usize; 7],
    _get_event_queue: usize,
    get_exception: unsafe extern "C" fn(*mut *mut Obj) -> HResult,
    clear_exception: unsafe extern "C" fn() -> HResult,
}

/// A COM/XPCOM object: a pointer to its vtable.
#[repr(C)]
struct Obj {
    vtbl: *const usize,
}

/// Owned interface pointer, released on drop.
struct Com(*mut Obj);

impl Com {
    /// Vtable entry `idx` (QueryInterface = 0, AddRef = 1, Release = 2, then the interface's own).
    unsafe fn method<F: Copy>(&self, idx: usize) -> F {
        std::mem::transmute_copy(&*(*self.0).vtbl.add(idx))
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let release: unsafe extern "C" fn(*mut Obj) -> u32 = self.method(2);
                release(self.0);
            }
        }
    }
}

/// The loaded library and its initialized client; uninitialized on drop.
struct Glue {
    api: *const CApi,
    _lib: Library,
}

impl Glue {
    fn load() -> Result<Glue, Error> {
        if let Some(home) = std::env::var_os("VBOX_APP_HOME") {
            return Glue::load_from(Path::new(&home));
        }
        let mut errors = Vec::new();
        for dir in SEARCH_DIRS {
            // VBoxXPCOMC locates the rest of VirtualBox through VBOX_APP_HOME, as the C glue sets it.
            std::env::set_var("VBOX_APP_HOME", dir);
            match Glue::load_from(Path::new(dir)) {
                Ok(glue) => return Ok(glue),
                Err(Error::LibraryNotFound(e) | Error::LibraryIncompatible(e)) => errors.push(e),
                Err(e) => return Err(e),
            }
        }
        std::env::remove_var("VBOX_APP_HOME");
        Err(Error::LibraryNotFound(errors.join("; ")))
    }

    fn load_from(dir: &Path) -> Result<Glue, Error> {
        let path = dir.join(LIB_NAME);
        let lib =
            unsafe { Library::new(&path) }.map_err(|e| Error::LibraryNotFound(e.to_string()))?;
        let api = unsafe {
            let get: libloading::Symbol<unsafe extern "C" fn(u32) -> *const CApi> = lib
                .get(b"VBoxGetCAPIFunctions\0")
                .map_err(|e| Error::LibraryIncompatible(e.to_string()))?;
            get(CAPI_VERSION)
        };
        // Same check as VBoxCAPIGlue.c: same major, minor at least ours.
        let version = unsafe { api.as_ref() }.map(|api| api.version);
        match version {
            Some(v) if v >> 16 == CAPI_VERSION >> 16 && v & 0xffff >= CAPI_VERSION & 0xffff => {}
            _ => {
                return Err(Error::LibraryIncompatible(format!(
                    "{}: C API version {:#x?}, need {:#x}",
                    path.display(),
                    version,
                    CAPI_VERSION
                )))
            }
        }
        Ok(Glue { api, _lib: lib })
    }

    fn api(&self) -> &CApi {
        unsafe { &*self.api }
    }

    fn check(&self, call: &'static str, rc: HResult) -> Result<(), Error> {
        if rc & 0x8000_0000 == 0 {
            return Ok(());
        }
        Err(Error::Api {
            call,
            rc,
            text: self.take_error_text(),
        })
    }

    /// Text of the current thread's pending VirtualBox error, which is then cleared.
    fn take_error_text(&self) -> Option<String> {
        unsafe {
            let mut ex = ptr::null_mut();
            if (self.api().get_exception)(&mut ex) & 0x8000_0000 != 0 || ex.is_null() {
                return None;
            }
            let ex = Com(ex);
            (self.api().clear_exception)();
            let qi: unsafe extern "C" fn(*mut Obj, *const NsId, *mut *mut Obj) -> HResult =
                ex.method(0);
            let mut info = ptr::null_mut();
            if qi(ex.0, &IID_IVIRTUALBOXERRORINFO, &mut info) & 0x8000_0000 != 0 || info.is_null() {
                return None;
            }
            let info = Com(info);
            let get_text: unsafe extern "C" fn(*mut Obj, *mut *mut u16) -> HResult =
                info.method(17); // IVirtualBoxErrorInfo::GetText
            let mut text = ptr::null_mut();
            if get_text(info.0, &mut text) & 0x8000_0000 != 0 || text.is_null() {
                return None;
            }
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            (self.api().com_unalloc_string)(text.cast());
            Some(s)
        }
    }

    /// Calls an interface-returning getter at vtable index `idx` of `obj`.
    fn get(&self, obj: &Com, idx: usize, call: &'static str) -> Result<Com, Error> {
        let mut out = ptr::null_mut();
        unsafe {
            let getter: unsafe extern "C" fn(*mut Obj, *mut *mut Obj) -> HResult = obj.method(idx);
            self.check(call, getter(obj.0, &mut out))?;
        }
        Ok(Com(out))
    }
}

impl Drop for Glue {
    fn drop(&mut self) {
        unsafe { (self.api().client_uninitialize)() }
    }
}

/// A shared session on a running VM, unlocked on drop.
///
/// Not `Send`/`Sync`: XPCOM was initialized on the creating thread, use it from there.
pub struct Vm {
    // Field order is drop order: interfaces first, the client and library last.
    debugger: Com,
    console: Com,
    session: Com,
    _vbox: Com,
    _client: Com,
    glue: Glue,
}

impl Vm {
    /// Loads the VirtualBox C API (`VBOX_APP_HOME`, else the standard install directories),
    /// then locks a shared session on the running VM `name`.
    pub fn attach(name: &str) -> Result<Vm, Error> {
        let glue = Glue::load()?;
        let mut client = ptr::null_mut();
        let rc = unsafe { (glue.api().client_initialize)(ptr::null(), &mut client) };
        let client = Com(client);
        glue.check("ClientInitialize", rc)?;
        let vbox = glue.get(&client, 3, "IVirtualBoxClient::GetVirtualBox")?;
        let session = glue.get(&client, 4, "IVirtualBoxClient::GetSession")?;

        let name_utf16: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut machine = ptr::null_mut();
        let rc = unsafe {
            let find: unsafe extern "C" fn(*mut Obj, *const u16, *mut *mut Obj) -> HResult =
                vbox.method(49);
            find(vbox.0, name_utf16.as_ptr(), &mut machine)
        };
        let machine = Com(machine);
        if rc == VBOX_E_OBJECT_NOT_FOUND {
            glue.take_error_text();
            return Err(Error::VmNotFound(name.to_string()));
        }
        glue.check("IVirtualBox::FindMachine", rc)?;

        let mut state = 0;
        unsafe {
            let get_state: unsafe extern "C" fn(*mut Obj, *mut u32) -> HResult = machine.method(61);
            glue.check("IMachine::GetState", get_state(machine.0, &mut state))?;
        }
        if !MACHINE_STATES_ONLINE.contains(&state) {
            return Err(Error::VmNotRunning {
                name: name.to_string(),
                state,
            });
        }
        unsafe {
            let lock: unsafe extern "C" fn(*mut Obj, *mut Obj, u32) -> HResult =
                machine.method(131);
            glue.check(
                "IMachine::LockMachine",
                lock(machine.0, session.0, LOCK_TYPE_SHARED),
            )?;
        }

        // From here on, dropping `vm` unlocks the session.
        let mut vm = Vm {
            debugger: Com(ptr::null_mut()),
            console: Com(ptr::null_mut()),
            session,
            _vbox: vbox,
            _client: client,
            glue,
        };
        vm.console = vm.glue.get(&vm.session, 8, "ISession::GetConsole")?;
        vm.debugger = vm.glue.get(&vm.console, 9, "IConsole::GetDebugger")?;
        Ok(vm)
    }

    /// Fills `buf` with guest physical memory starting at `paddr` (`IMachineDebugger::readPhysicalMemory`).
    pub fn read_physical(&self, paddr: u64, buf: &mut [u8]) -> Result<(), Error> {
        let read: unsafe extern "C" fn(*mut Obj, i64, u32, *mut u32, *mut *mut u8) -> HResult =
            unsafe { self.debugger.method(48) };
        let mut addr = paddr;
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let (mut len, mut data) = (0u32, ptr::null_mut());
            let rc = unsafe {
                read(
                    self.debugger.0,
                    addr as i64,
                    chunk.len() as u32,
                    &mut len,
                    &mut data,
                )
            };
            self.glue
                .check("IMachineDebugger::ReadPhysicalMemory", rc)?;
            let result = if len as usize == chunk.len() && !data.is_null() {
                chunk.copy_from_slice(unsafe { std::slice::from_raw_parts(data, chunk.len()) });
                Ok(())
            } else {
                Err(Error::Api {
                    call: "IMachineDebugger::ReadPhysicalMemory",
                    rc: E_UNEXPECTED,
                    text: Some(format!("returned {} bytes, expected {}", len, chunk.len())),
                })
            };
            unsafe { (self.glue.api().com_unalloc_string)(data.cast()) };
            result?;
            addr += chunk.len() as u64;
        }
        Ok(())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            let unlock: unsafe extern "C" fn(*mut Obj) -> HResult = self.session.method(17);
            unlock(self.session.0);
        }
    }
}
