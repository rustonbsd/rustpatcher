use once_cell::sync::OnceCell;

pub static APP_VERSION: OnceCell<&'static str> = OnceCell::new();

#[doc(hidden)]
pub fn __set_version(version: &'static str) {
    let _ = APP_VERSION.set(version);
}

pub fn get_app_version() -> &'static str {
    APP_VERSION.get().expect("Version not initialized")
}