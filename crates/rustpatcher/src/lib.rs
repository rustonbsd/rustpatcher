mod version;
mod patch;
mod patcher;
mod publisher;
mod updater;
mod distributor;

#[doc(hidden)]
pub mod embed;

#[doc(hidden)]
pub use version::Version;

#[doc(hidden)]
pub use patch::{Patch,PatchInfo};

use publisher::Publisher;
use updater::Updater;
use distributor::Distributor;

use embed::get_owner_pub_key;

pub use rustpatcher_macros::*;
pub use updater::UpdaterMode;
pub use patcher::spawn;
