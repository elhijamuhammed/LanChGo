#[cfg(target_os = "windows")]
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    UI::{
        Shell::{DragAcceptFiles, DragFinish, DragQueryFileW, HDROP},
        WindowsAndMessaging::{
            CallWindowProcW, GetWindowLongPtrW, SetWindowLongPtrW, GWLP_WNDPROC, WM_DESTROY,
            WM_DROPFILES, WNDPROC,
        },
    },
};

#[cfg(target_os = "windows")]
type DropCallback = Box<dyn Fn(Vec<PathBuf>) + Send + Sync + 'static>;

#[cfg(target_os = "windows")]
static DROP_CALLBACK: OnceLock<Mutex<Option<DropCallback>>> = OnceLock::new();

#[cfg(target_os = "windows")]
static ORIGINAL_WNDPROC: OnceLock<Mutex<isize>> = OnceLock::new();

#[cfg(target_os = "windows")]
pub unsafe fn install_file_drop_handler(
    hwnd: HWND,
    on_files_dropped: impl Fn(Vec<PathBuf>) + Send + Sync + 'static,
) {
    DROP_CALLBACK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .replace(Box::new(on_files_dropped));

    DragAcceptFiles(hwnd, true);

    let old_proc = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);

    ORIGINAL_WNDPROC
        .get_or_init(|| Mutex::new(0))
        .lock()
        .unwrap()
        .clone_from(&old_proc);

    SetWindowLongPtrW(hwnd, GWLP_WNDPROC, window_proc as isize);
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_DROPFILES => {
            let hdrop = HDROP(wparam.0 as *mut core::ffi::c_void);
            let paths = collect_dropped_paths(hdrop);

            DragFinish(hdrop);

            if !paths.is_empty() {
                if let Some(lock) = DROP_CALLBACK.get() {
                    if let Some(callback) = lock.lock().unwrap().as_ref() {
                        callback(paths);
                    }
                }
            }

            LRESULT(0)
        }

        WM_DESTROY => {
            DragAcceptFiles(hwnd, false);
            call_original_window_proc(hwnd, msg, wparam, lparam)
        }

        _ => call_original_window_proc(hwnd, msg, wparam, lparam),
    }
}

#[cfg(target_os = "windows")]
unsafe fn call_original_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let old_proc = ORIGINAL_WNDPROC
        .get()
        .map(|m| *m.lock().unwrap())
        .unwrap_or(0);

    if old_proc == 0 {
        return LRESULT(0);
    }

    let original: WNDPROC = std::mem::transmute(old_proc);
    CallWindowProcW(original, hwnd, msg, wparam, lparam)
}

#[cfg(target_os = "windows")]
unsafe fn collect_dropped_paths(hdrop: HDROP) -> Vec<PathBuf> {
    let count = DragQueryFileW(hdrop, 0xFFFFFFFF, None);
    let mut paths = Vec::new();

    for i in 0..count {
        let len = DragQueryFileW(hdrop, i, None);
        if len == 0 {
            continue;
        }

        let mut buffer = vec![0u16; (len + 1) as usize];
        DragQueryFileW(hdrop, i, Some(&mut buffer));

        let path = OsString::from_wide(&buffer[..len as usize]);
        paths.push(PathBuf::from(path));
    }

    paths
}
