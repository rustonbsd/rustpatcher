mod distributor;
mod patch;
mod patcher;
mod publisher;
mod updater;
mod version;

#[cfg(target_os = "macos")]
pub mod macho;

#[doc(hidden)]
pub mod embed;

#[doc(hidden)]
pub use version::Version;

#[doc(hidden)]
pub use patch::{Patch, PatchInfo};

use distributor::Distributor;
use publisher::Publisher;
use updater::Updater;

use embed::get_owner_pub_key;

pub use patcher::spawn;
pub use rustpatcher_macros::*;
pub use updater::UpdaterMode;
