mod version;
mod patch;
mod patcher;
mod publisher;
mod updater;
mod distributor;

// hide from docs
#[doc(hidden)]
pub mod embed;

#[doc(hidden)]
pub use version::Version;

#[doc(hidden)]
pub use patch::{Patch,PatchInfo};

use publisher::Publisher;
use updater::Updater;
pub use updater::UpdaterMode;
use distributor::Distributor;

pub use rustpatcher_macros::*;
use embed::get_owner_pub_key;

pub use patcher::spawn;
