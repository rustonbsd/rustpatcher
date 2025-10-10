use std::{fmt::Display, str::FromStr};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Version(pub i32, pub i32, pub i32);

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            bail!("wrong version format")
        }

        let major = parts[0].parse::<i32>()?;
        let minor = parts[1].parse::<i32>()?;
        let patch = parts[2].parse::<i32>()?;

        Ok(Version(major, minor, patch))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_sum: i128 = ((i32::MAX as i128).pow(2) * self.0 as i128)
            + ((i32::MAX as i128).pow(1) * self.1 as i128)
            + self.2 as i128;
        let other_sum: i128 = ((i32::MAX as i128).pow(2) * other.0 as i128)
            + ((i32::MAX as i128).pow(1) * other.1 as i128)
            + other.2 as i128;
        self_sum.cmp(&other_sum)
    }

    fn max(self, other: Self) -> Self
    where
        Self: Sized,
    {
        if other > self { other } else { self }
    }

    fn min(self, other: Self) -> Self
    where
        Self: Sized,
    {
        if other < self { other } else { self }
    }

    fn clamp(self, min: Self, max: Self) -> Self
    where
        Self: Sized,
    {
        assert!(min <= max);
        if self < min {
            min
        } else if self > max {
            max
        } else {
            self
        }
    }
}

impl Version {
    pub fn new(major: i32, minor: i32, patch: i32) -> Self {
        Version(major, minor, patch)
    }

    pub fn current() -> anyhow::Result<Self> {
        let v = Version::from_str(crate::embed::get_app_version());
        warn!("Current version: {:?}", v);
        v
    }
}
