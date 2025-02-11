use once_cell::sync::OnceCell;

pub static APP_VERSION: OnceCell<&'static str> = OnceCell::new();

pub fn get_app_version() -> &'static str {
    APP_VERSION.get().expect("Version not initialized")
}