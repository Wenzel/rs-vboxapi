//! Minimal binding to VirtualBox's C API, loaded at runtime (dlopen) from an installed VirtualBox.
//!
//! It covers only what libmicrovmi's MachineDebugger access method needs: attach a shared
//! session to a running VM by name, read guest physical memory through `IMachineDebugger` and
//! list the guest's RAM ranges.
//!
//! The function table and vtable indices are hand-written from `VBoxCAPI_v7_3.h`
//! (`sdk/bindings/c/include` of a VirtualBox build); `VBoxCAPIGlue.c` is the loader reference.

use std::cell::Cell;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::ops::Range;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;
use std::thread::ThreadId;

use libloading::Library;

type HResult = u32;

// shortcut: Linux/XPCOM only (Windows uses VBoxCAPI.dll and IDispatch-based vtables), extend for Windows CI.
const LIB_NAME: &str = "VBoxXPCOMC.so";
/// Searched in order when `VBOX_APP_HOME` is not set, like `VBoxCGlueInit`.
const SEARCH_DIRS: &[&str] = &["/opt/VirtualBox", "/usr/lib/virtualbox"];

const CAPI_VERSION: u32 = 0x0004_0001;
const VBOX_E_OBJECT_NOT_FOUND: HResult = 0x80BB_0001;
const E_UNEXPECTED: HResult = 0x8000_FFFF;
/// Bytes per `readPhysicalMemory` call.
const READ_CHUNK: usize = 1 << 20;
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
    #[error("guest physical range {paddr:#x} + {len:#x} is out of range")]
    AddressOutOfRange { paddr: u64, len: usize },
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
    client_thread_initialize: unsafe extern "C" fn() -> HResult,
    _client_thread_uninitialize: usize,
    _client_uninitialize: usize,
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

/// The process-wide C API: VirtualBox allows one `IVirtualBoxClient` per process, so every
/// [`Vm`] shares it. It is never uninitialized and the library is never unloaded (both live
/// until the process exits), which keeps attach → drop → attach and concurrent `Vm`s safe.
struct Client {
    api: &'static CApi,
    vbox: Com,
    vbox_client: Com,
    thread: ThreadId,
}

// Safety: the function table is immutable, and VirtualBox's XPCOM proxies may be called from
// any thread that initialized COM, which `client()` ensures before handing out the reference.
unsafe impl Send for Client {}
unsafe impl Sync for Client {}

static CLIENT: Mutex<Option<&'static Client>> = Mutex::new(None);

thread_local! {
    static THREAD_COM: Cell<bool> = const { Cell::new(false) };
}

/// Returns the process-wide client, loading and initializing it on first use, and initializes
/// COM on the calling thread if it is not the one that initialized the client.
fn client() -> Result<&'static Client, Error> {
    let mut slot = CLIENT.lock().unwrap_or_else(|e| e.into_inner());
    let client = match *slot {
        Some(client) => client,
        None => {
            let client: &'static Client = Box::leak(Box::new(Client::init()?));
            *slot = Some(client);
            THREAD_COM.with(|c| c.set(true));
            client
        }
    };
    drop(slot);
    if client.thread != std::thread::current().id() && !THREAD_COM.with(Cell::get) {
        // shortcut: never paired with pfnClientThreadUninitialize, threads exit with COM initialized.
        let rc = unsafe { (client.api.client_thread_initialize)() };
        client.check("ClientThreadInitialize", rc)?;
        THREAD_COM.with(|c| c.set(true));
    }
    Ok(client)
}

fn failed(rc: HResult) -> bool {
    rc & 0x8000_0000 != 0
}

fn version_compatible(v: u32) -> bool {
    // Same check as VBoxCAPIGlue.c: same major, minor at least ours.
    v >> 16 == CAPI_VERSION >> 16 && v & 0xffff >= CAPI_VERSION & 0xffff
}

fn version_string(v: Option<u32>) -> String {
    v.map_or("unknown".to_string(), |v| {
        format!("{}.{}", v >> 16, v & 0xffff)
    })
}

/// Takes ownership of an interface pointer returned by a successful call; null is an error.
fn owned(call: &'static str, obj: *mut Obj) -> Result<Com, Error> {
    if obj.is_null() {
        return Err(Error::Api {
            call,
            rc: E_UNEXPECTED,
            text: Some("returned a null object".to_string()),
        });
    }
    Ok(Com(obj))
}

impl Client {
    fn init() -> Result<Client, Error> {
        let api = load_api()?;
        let mut client = ptr::null_mut();
        let rc = unsafe { (api.client_initialize)(ptr::null(), &mut client) };
        // A failed ClientInitialize has already uninitialized: no error info to fetch.
        if failed(rc) {
            return Err(Error::Api {
                call: "ClientInitialize",
                rc,
                text: None,
            });
        }
        let client = owned("ClientInitialize", client)?;
        let mut this = Client {
            api,
            vbox: Com(ptr::null_mut()),
            vbox_client: client,
            thread: std::thread::current().id(),
        };
        this.vbox = this.get(&this.vbox_client, 3, "IVirtualBoxClient::GetVirtualBox")?;
        Ok(this)
    }

    fn check(&self, call: &'static str, rc: HResult) -> Result<(), Error> {
        if !failed(rc) {
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
            if failed((self.api.get_exception)(&mut ex)) || ex.is_null() {
                return None;
            }
            let ex = Com(ex);
            (self.api.clear_exception)();
            let qi: unsafe extern "C" fn(*mut Obj, *const NsId, *mut *mut Obj) -> HResult =
                ex.method(0);
            let mut info = ptr::null_mut();
            if failed(qi(ex.0, &IID_IVIRTUALBOXERRORINFO, &mut info)) || info.is_null() {
                return None;
            }
            let info = Com(info);
            let get_text: unsafe extern "C" fn(*mut Obj, *mut *mut u16) -> HResult =
                info.method(17); // IVirtualBoxErrorInfo::GetText
            let mut text = ptr::null_mut();
            if failed(get_text(info.0, &mut text)) {
                return None;
            }
            self.take_string(text)
        }
    }

    /// Converts and frees a string returned by the API; `None` if null.
    unsafe fn take_string(&self, s: *mut u16) -> Option<String> {
        if s.is_null() {
            return None;
        }
        let len = (0..).take_while(|&i| *s.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, len));
        (self.api.com_unalloc_string)(s.cast());
        Some(out)
    }

    /// Calls an interface-returning getter at vtable index `idx` of `obj`.
    fn get(&self, obj: &Com, idx: usize, call: &'static str) -> Result<Com, Error> {
        let mut out = ptr::null_mut();
        unsafe {
            let getter: unsafe extern "C" fn(*mut Obj, *mut *mut Obj) -> HResult = obj.method(idx);
            self.check(call, getter(obj.0, &mut out))?;
        }
        owned(call, out)
    }
}

/// Loads the library from `VBOX_APP_HOME`, else from the first standard directory that has it.
/// A library found but incompatible stops the search.
/// The library is never unloaded.
fn load_api() -> Result<&'static CApi, Error> {
    if let Some(home) = std::env::var_os("VBOX_APP_HOME") {
        return load_api_from(Path::new(&home));
    }
    // Unlike VBoxCAPIGlue.c, VBOX_APP_HOME is not set here: XPCOM then falls back to the
    // install's compiled-in RTPathAppPrivateArch(), which is that same directory.
    for dir in SEARCH_DIRS {
        match load_api_from(Path::new(dir)) {
            Err(Error::LibraryNotFound(_)) => continue,
            result => return result,
        }
    }
    Err(Error::LibraryNotFound(format!(
        "no {} in {}",
        LIB_NAME,
        SEARCH_DIRS.join(" or ")
    )))
}

fn load_api_from(dir: &Path) -> Result<&'static CApi, Error> {
    let path = dir.join(LIB_NAME);
    let lib = unsafe { Library::new(&path) }.map_err(|e| Error::LibraryNotFound(e.to_string()))?;
    let api = unsafe {
        let get: libloading::Symbol<unsafe extern "C" fn(u32) -> *const CApi> = lib
            .get(b"VBoxGetCAPIFunctions\0")
            .map_err(|e| Error::LibraryIncompatible(e.to_string()))?;
        get(CAPI_VERSION).as_ref()
    };
    match api {
        Some(api) if version_compatible(api.version) => {
            std::mem::forget(lib); // keeps `api` valid for the process lifetime
            Ok(api)
        }
        _ => Err(Error::LibraryIncompatible(format!(
            "{}: C API version {}, need {}",
            path.display(),
            version_string(api.map(|api| api.version)),
            version_string(Some(CAPI_VERSION))
        ))),
    }
}

/// A shared session on a running VM, unlocked on drop.
///
/// Not `Send`/`Sync`: use it on the thread that attached. Any number of `Vm`s may be alive at
/// once, on any threads.
pub struct Vm {
    // Field order is drop order.
    debugger: Com,
    console: Com,
    session: Com,
    client: &'static Client,
}

impl Vm {
    /// Locks a shared session on the running VM `name`.
    ///
    /// The first call in the process loads the VirtualBox C API from `VBOX_APP_HOME`, else from
    /// `/opt/VirtualBox` or `/usr/lib/virtualbox` (only for an installed VirtualBox, whose
    /// compiled-in path XPCOM uses), and keeps it loaded until the process exits.
    pub fn attach(name: &str) -> Result<Vm, Error> {
        let client = client()?;
        let session = client.get(&client.vbox_client, 4, "IVirtualBoxClient::GetSession")?;

        let name_utf16: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut machine = ptr::null_mut();
        let rc = unsafe {
            let find: unsafe extern "C" fn(*mut Obj, *const u16, *mut *mut Obj) -> HResult =
                client.vbox.method(49);
            find(client.vbox.0, name_utf16.as_ptr(), &mut machine)
        };
        if rc == VBOX_E_OBJECT_NOT_FOUND {
            client.take_error_text();
            return Err(Error::VmNotFound(name.to_string()));
        }
        client.check("IVirtualBox::FindMachine", rc)?;
        let machine = owned("IVirtualBox::FindMachine", machine)?;

        let mut state = 0;
        unsafe {
            let get_state: unsafe extern "C" fn(*mut Obj, *mut u32) -> HResult = machine.method(61);
            client.check("IMachine::GetState", get_state(machine.0, &mut state))?;
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
            client.check(
                "IMachine::LockMachine",
                lock(machine.0, session.0, LOCK_TYPE_SHARED),
            )?;
        }
        drop(machine);

        // From here on, dropping `vm` unlocks the session.
        let mut vm = Vm {
            debugger: Com(ptr::null_mut()),
            console: Com(ptr::null_mut()),
            session,
            client,
        };
        vm.console = client.get(&vm.session, 8, "ISession::GetConsole")?;
        vm.debugger = client.get(&vm.console, 9, "IConsole::GetDebugger")?;
        Ok(vm)
    }

    /// Fills `buf` with guest physical memory starting at `paddr` (`IMachineDebugger::readPhysicalMemory`).
    pub fn read_physical(&self, paddr: u64, buf: &mut [u8]) -> Result<(), Error> {
        let out_of_range = || Error::AddressOutOfRange {
            paddr,
            len: buf.len(),
        };
        let end = i64::try_from(paddr)
            .ok()
            .and_then(|start| start.checked_add(i64::try_from(buf.len()).ok()?))
            .ok_or_else(out_of_range)?;
        let read: unsafe extern "C" fn(*mut Obj, i64, u32, *mut u32, *mut *mut u8) -> HResult =
            unsafe { self.debugger.method(48) };
        let mut addr = end - buf.len() as i64;
        for chunk in buf.chunks_mut(READ_CHUNK) {
            let (mut len, mut data) = (0u32, ptr::null_mut());
            let rc = unsafe {
                read(
                    self.debugger.0,
                    addr,
                    chunk.len() as u32,
                    &mut len,
                    &mut data,
                )
            };
            self.client
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
            unsafe { (self.client.api.com_unalloc_string)(data.cast()) };
            result?;
            addr += chunk.len() as i64;
        }
        Ok(())
    }

    /// The guest-physical RAM ranges (pages of type RAM, so excluding MMIO, MMIO2 and ROM),
    /// sorted by address and merged when contiguous, parsed from the PGM `phys` info handler.
    pub fn ram_ranges(&self) -> Result<Vec<Range<u64>>, Error> {
        const CALL: &str = "IMachineDebugger::Info";
        let utf16 = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (name, args) = (utf16("phys"), utf16("verbose"));
        let mut out = ptr::null_mut();
        let text = unsafe {
            let info: unsafe extern "C" fn(
                *mut Obj,
                *const u16,
                *const u16,
                *mut *mut u16,
            ) -> HResult = self.debugger.method(43);
            self.client.check(
                CALL,
                info(self.debugger.0, name.as_ptr(), args.as_ptr(), &mut out),
            )?;
            self.client.take_string(out)
        };
        let ranges = text.as_deref().map(parse_ram_ranges).unwrap_or_default();
        if ranges.is_empty() {
            return Err(Error::Api {
                call: CALL,
                rc: E_UNEXPECTED,
                text: Some(format!("no RAM range in \"phys\" info: {:?}", text)),
            });
        }
        Ok(ranges)
    }
}

/// Parses the page-type lines of `pgmR3PhysInfo` (`info phys verbose`): per RAM range, an
/// indented `{first:016x}-{last:016x} {type}[ {desc}]` line per run of same-type pages, with
/// type `RAM`, `MMIO`, `MMIO2`, `ROM`, `ROM-shadowed`, ... Keeps `RAM` runs only, merged.
fn parse_ram_ranges(text: &str) -> Vec<Range<u64>> {
    let mut ranges: Vec<Range<u64>> = text
        .lines()
        .filter(|l| l.starts_with(' '))
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let (first, last) = words.next()?.split_once('-')?;
            if words.next()? != "RAM" {
                return None;
            }
            let first = u64::from_str_radix(first, 16).ok()?;
            let end = u64::from_str_radix(last, 16).ok()?.checked_add(1)?;
            Some(first..end)
        })
        .collect();
    ranges.sort_by_key(|r| r.start);
    ranges.dedup_by(|next, prev| {
        let contiguous = next.start <= prev.end;
        if contiguous {
            prev.end = prev.end.max(next.end);
        }
        contiguous
    });
    ranges
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            let unlock: unsafe extern "C" fn(*mut Obj) -> HResult = self.session.method(17);
            unlock(self.session.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_check() {
        assert!(version_compatible(0x0004_0001));
        assert!(version_compatible(0x0004_0002));
        assert!(!version_compatible(0x0004_0000));
        assert!(!version_compatible(0x0005_0001));
        assert!(!version_compatible(0x0003_0001));
        assert_eq!(version_string(Some(0x0005_0000)), "5.0");
        assert_eq!(version_string(None), "unknown");
    }

    #[test]
    fn ram_ranges_parse() {
        // `VBoxManage debugvm <vm> info phys verbose` of a 5 GiB guest.
        let text = include_str!("../testdata/phys-5g.txt");
        assert_eq!(
            parse_ram_ranges(text),
            vec![
                0..0xa0000,
                0x100000..0xe000_0000,
                0x1_0000_0000..0x1_6000_0000
            ]
        );
        assert!(parse_ram_ranges("RAM ranges (pVM=0)\n").is_empty());
    }
}
