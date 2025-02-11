use once_cell::sync::OnceCell;

static APP_VERSION: OnceCell<&'static str> = OnceCell::new();

pub fn set_app_version(version: &'static str) -> Result<(), &'static str> {
    APP_VERSION.set(version)
        .map_err(|_| "Version already set")
}

pub fn get_app_version() -> &'static str {
    APP_VERSION.get().expect("Version not initialized")
}