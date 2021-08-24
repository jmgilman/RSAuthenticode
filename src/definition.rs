use crate::{authenticode::AuthenticodeData, error::APIError, version::read_version};


pub struct Definition {
    pub path: String,
}

impl Definition {
    pub fn new(path: &str) -> Definition {
        Definition {
            path: path.to_string()
        }
    }

    pub fn authenticode_data(&self) -> Result<AuthenticodeData, APIError> {
        AuthenticodeData::new(self.path.as_str())
    }

    pub fn version(&self) -> Option<String> {
        read_version(self.path.as_str())
    }
}