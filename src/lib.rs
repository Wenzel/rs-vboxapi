//! Minimal binding to VirtualBox's C API, loaded at runtime (dlopen) from an installed VirtualBox.
//!
//! It covers only what libmicrovmi's MachineDebugger access method needs: attach a shared
//! session to a running VM by name, read and write guest physical memory through `IMachineDebugger`, list
//! the guest's RAM ranges, pause and resume it, and get its vCPU count.
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
const E_NOTIMPL: HResult = 0x8000_4001;
/// Bytes per `readPhysicalMemory` call.
const READ_CHUNK: usize = 1 << 20;
/// Bytes per `writePhysicalMemory` call.
const WRITE_CHUNK: usize = 1 << 20;
const LOCK_TYPE_SHARED: u32 = 1;
/// `MachineState_FirstOnline..=MachineState_LastOnline`: states with a VM process to talk to.
const MACHINE_STATES_ONLINE: std::ops::RangeInclusive<u32> = 6..=19;
const MACHINE_STATE_RUNNING: u32 = 6;
const MACHINE_STATE_PAUSED: u32 = 7;
/// Teleporting, LiveSnapshotting, TeleportingPausedVM, OnlineSnapshotting: pause and resume are
/// VirtualBox's own until the operation ends.
const MACHINE_STATES_BUSY: [u32; 4] = [9, 10, 15, 19];
/// Pause or resume attempts when another client keeps flipping the state.
const PAUSE_RESUME_ATTEMPTS: usize = 3;

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
    #[error("VM is busy: live snapshot or teleport in progress (MachineState {0})")]
    VmBusy(u32),
    #[error("VM is in MachineState {state}, expected {expected}")]
    UnexpectedState { state: u32, expected: u32 },
    #[error("this VirtualBox does not implement IMachineDebugger physical memory access: it lacks the IMachineDebugger memory access patch (build Wenzel/virtualbox branch vmi/machinedebugger, or use a VirtualBox release that includes it)")]
    MemoryAccessNotImplemented,
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

    /// Calls a `u32` getter at vtable index `idx` of `obj`.
    fn get_u32(&self, obj: &Com, idx: usize, call: &'static str) -> Result<u32, Error> {
        let mut out = 0;
        unsafe {
            let getter: unsafe extern "C" fn(*mut Obj, *mut u32) -> HResult = obj.method(idx);
            self.check(call, getter(obj.0, &mut out))?;
        }
        Ok(out)
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
    cpu_count: u32,
}

impl Vm {
    /// Locks a shared session on the running VM `name`.
    ///
    /// The first call in the process loads the VirtualBox C API from `VBOX_APP_HOME`, else from
    /// `/opt/VirtualBox` or `/usr/lib/virtualbox` (only for an installed VirtualBox, whose
    /// compiled-in path XPCOM uses), and keeps it loaded until the process exits.
    ///
    /// Fails with [`Error::MemoryAccessNotImplemented`] on a VirtualBox without the memory access patch.
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

        let state = client.get_u32(&machine, 61, "IMachine::GetState")?;
        if !MACHINE_STATES_ONLINE.contains(&state) {
            return Err(Error::VmNotRunning {
                name: name.to_string(),
                state,
            });
        }
        // shortcut: CPUCount is the maximum with CPU hot-plug, not the plugged vCPUs; count those if hot-plug matters.
        let cpu_count = client.get_u32(&machine, 21, "IMachine::GetCPUCount")?;
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
            cpu_count,
        };
        vm.console = client.get(&vm.session, 8, "ISession::GetConsole")?;
        vm.debugger = client.get(&vm.console, 9, "IConsole::GetDebugger")?;
        // Probe one byte, so a VirtualBox without the memory access patch fails here, not on
        // the first read. Physical address 0 is RAM on a PC; any other error is left to the reads.
        match vm.read_physical(0, &mut [0]) {
            Err(e @ Error::MemoryAccessNotImplemented) => return Err(e),
            Err(e) => log::debug!("memory access probe failed: {}", e),
            Ok(()) => {}
        }
        Ok(vm)
    }

    /// The VM's vCPU count (`IMachine::CPUCount`), read at attach.
    ///
    /// With CPU hot-plug enabled, this is the maximum vCPU count, not the vCPUs plugged in.
    pub fn cpu_count(&self) -> u32 {
        self.cpu_count
    }

    /// Pauses the VM (`IConsole::pause`); a no-op if it is already paused.
    ///
    /// Synchronous: on success every vCPU has stopped executing guest code and the VM is in the
    /// `Paused` state, as other API clients (e.g. `VBoxManage showvminfo`) see it.
    /// Not counted: a single [`Vm::resume`] resumes the VM however many times it was paused, by
    /// anyone. During a live snapshot or teleport it fails with [`Error::VmBusy`].
    pub fn pause(&self) -> Result<(), Error> {
        self.pause_or_resume(
            30,
            "IConsole::Pause",
            MACHINE_STATE_PAUSED,
            MACHINE_STATE_RUNNING,
        )
    }

    /// Resumes the VM (`IConsole::resume`); a no-op if it is already running.
    /// During a live snapshot or teleport it fails with [`Error::VmBusy`].
    pub fn resume(&self) -> Result<(), Error> {
        self.pause_or_resume(
            31,
            "IConsole::Resume",
            MACHINE_STATE_RUNNING,
            MACHINE_STATE_PAUSED,
        )
    }

    /// Calls the no-argument `IConsole` method `idx`, which fails if the VM is already in `target`
    /// state, then checks the state. Succeeds only in `target` state; retried while another
    /// client moves the VM back to `from` in between.
    fn pause_or_resume(
        &self,
        idx: usize,
        call: &'static str,
        target: u32,
        from: u32,
    ) -> Result<(), Error> {
        let mut last = None;
        for _ in 0..PAUSE_RESUME_ATTEMPTS {
            let rc = unsafe {
                let f: unsafe extern "C" fn(*mut Obj) -> HResult = self.console.method(idx);
                f(self.console.0)
            };
            // taken before the state query, which may overwrite the thread's error info
            let err = failed(rc).then(|| Error::Api {
                call,
                rc,
                text: self.client.take_error_text(),
            });
            let state = match self.client.get_u32(&self.console, 4, "IConsole::GetState") {
                Ok(state) => state,
                Err(e) => return Err(err.unwrap_or(e)),
            };
            if state == target {
                return Ok(());
            }
            if MACHINE_STATES_BUSY.contains(&state) {
                return Err(Error::VmBusy(state));
            }
            let err = err.unwrap_or(Error::UnexpectedState {
                state,
                expected: target,
            });
            if state != from {
                return Err(err);
            }
            last = Some(err);
        }
        Err(last.expect("at least one attempt"))
    }

    /// Fills `buf` with guest physical memory starting at `paddr` (`IMachineDebugger::readPhysicalMemory`).
    /// Fails with [`Error::MemoryAccessNotImplemented`] on a VirtualBox without the memory access patch.
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
            if rc == E_NOTIMPL {
                self.client.take_error_text();
                return Err(Error::MemoryAccessNotImplemented);
            }
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

    /// Writes `buf` to guest physical memory starting at `paddr` (`IMachineDebugger::writePhysicalMemory`).
    ///
    /// Not atomic: on error, a prefix of `buf` may already be written. Pages that are not backed
    /// by host memory (MMIO, ballooned, unassigned) fail at the first such page, without touching
    /// any device. Fails with [`Error::MemoryAccessNotImplemented`] on a VirtualBox without the
    /// memory access patch.
    pub fn write_physical(&self, paddr: u64, buf: &[u8]) -> Result<(), Error> {
        let end = i64::try_from(paddr)
            .ok()
            .and_then(|start| start.checked_add(i64::try_from(buf.len()).ok()?))
            .ok_or(Error::AddressOutOfRange {
                paddr,
                len: buf.len(),
            })?;
        // XPCOM passes a safearray in-parameter as (element count, pointer).
        let write: unsafe extern "C" fn(*mut Obj, i64, u32, u32, *const u8) -> HResult =
            unsafe { self.debugger.method(49) };
        let mut addr = end - buf.len() as i64;
        for chunk in buf.chunks(WRITE_CHUNK) {
            let len = chunk.len() as u32;
            let rc = unsafe { write(self.debugger.0, addr, len, len, chunk.as_ptr()) };
            if rc == E_NOTIMPL {
                self.client.take_error_text();
                return Err(Error::MemoryAccessNotImplemented);
            }
            self.client
                .check("IMachineDebugger::WritePhysicalMemory", rc)?;
            addr += chunk.len() as i64;
        }
        Ok(())
    }

    /// The guest-physical RAM ranges (pages of type RAM, so excluding MMIO, MMIO2 and ROM),
    /// sorted by address and merged when contiguous, parsed from the PGM `phys` info handler.
    /// Never empty: no RAM range, or a page-type line that does not parse, is an error.
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
        parse_ram_ranges(text.as_deref().unwrap_or_default()).map_err(|e| Error::Api {
            call: CALL,
            rc: E_UNEXPECTED,
            text: Some(format!("\"phys\" info: {}", e)),
        })
    }
}

/// Parses the page-type lines of `pgmR3PhysInfo` (`info phys verbose`): per RAM range, an
/// indented `{first:016x}-{last:016x} {type}[ {desc}]` line per run of same-type pages, with
/// type `RAM`, `MMIO`, `MMIO2`, `ROM`, `ROM-shadowed`, ... Keeps `RAM` runs only, merged.
/// Every indented line must parse, so a format change can't silently lower the max address.
fn parse_ram_ranges(text: &str) -> Result<Vec<Range<u64>>, String> {
    let mut ranges = Vec::new();
    for line in text.lines().filter(|l| l.starts_with(' ')) {
        let parsed = || -> Option<(u64, u64, bool)> {
            let mut words = line.split_whitespace();
            let (first, last) = words.next()?.split_once('-')?;
            let is_ram = words.next()? == "RAM";
            Some((
                u64::from_str_radix(first, 16).ok()?,
                u64::from_str_radix(last, 16).ok()?,
                is_ram,
            ))
        };
        let (first, last, is_ram) =
            parsed().ok_or_else(|| format!("unexpected line {:?}", line))?;
        if is_ram {
            // An end-exclusive Range can't hold a range ending at u64::MAX.
            let end = last.checked_add(1).ok_or_else(|| {
                format!("RAM range ends at the top of the address space: {:?}", line)
            })?;
            ranges.push(first..end);
        }
    }
    if ranges.is_empty() {
        return Err(format!("no RAM range in {} lines", text.lines().count()));
    }
    ranges.sort_by_key(|r| r.start);
    ranges.dedup_by(|next, prev| {
        let contiguous = next.start <= prev.end;
        if contiguous {
            prev.end = prev.end.max(next.end);
        }
        contiguous
    });
    Ok(ranges)
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
            parse_ram_ranges(text).unwrap(),
            vec![
                0..0xa0000,
                0x100000..0xe000_0000,
                0x1_0000_0000..0x1_6000_0000
            ]
        );
        assert_eq!(
            parse_ram_ranges("RAM ranges (pVM=0)\nGC Phys Range\n").unwrap_err(),
            "no RAM range in 2 lines"
        );
        // A page-type line that doesn't parse, RAM or not, is an error, not a skipped range.
        for bad in [
            "    0000000100000000-15fffffff_ RAM",
            "    0000000100000000 RAM",
            "    0000000100000000-000000015fffffff",
            "    garbage",
        ] {
            let text = format!("{}\n    0000000000000000-000000000009ffff RAM\n", bad);
            assert!(parse_ram_ranges(&text)
                .unwrap_err()
                .starts_with("unexpected line"));
        }
        assert!(
            parse_ram_ranges("    0000000100000000-ffffffffffffffff RAM\n")
                .unwrap_err()
                .starts_with("RAM range ends at the top")
        );
        // Non-RAM lines may end at u64::MAX.
        assert_eq!(
            parse_ram_ranges("    0-fff RAM\n    ffffffff00000000-ffffffffffffffff MMIO\n")
                .unwrap(),
            vec![0..0x1000]
        );
    }
}
