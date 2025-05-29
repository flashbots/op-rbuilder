use std::path::PathBuf;

#[derive(Default, Debug)]
pub struct OpRbuilderConfig {
    auth_rpc_port: Option<u16>,
    jwt_secret_path: Option<PathBuf>,
    chain_config_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    http_port: Option<u16>,
    network_port: Option<u16>,
    builder_private_key: Option<String>,
    flashblocks_ws_url: Option<String>,
    chain_block_time: Option<u64>,
    flashbots_block_time: Option<u64>,
    with_revert_protection: Option<bool>,
    namespaces: Option<String>,
    extra_params: Option<String>,
}

impl OpRbuilderConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn auth_rpc_port(mut self, port: u16) -> Self {
        self.auth_rpc_port = Some(port);
        self
    }

    pub fn chain_config_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.chain_config_path = Some(path.into());
        self
    }

    pub fn data_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    pub fn network_port(mut self, port: u16) -> Self {
        self.network_port = Some(port);
        self
    }

    pub fn http_port(mut self, port: u16) -> Self {
        self.http_port = Some(port);
        self
    }

    pub fn with_builder_private_key(mut self, private_key: &str) -> Self {
        self.builder_private_key = Some(private_key.to_string());
        self
    }

    pub fn with_revert_protection(mut self, revert_protection: bool) -> Self {
        self.with_revert_protection = Some(revert_protection);
        self
    }

    pub fn with_flashblocks_ws_url(mut self, url: &str) -> Self {
        self.flashblocks_ws_url = Some(url.to_string());
        self
    }

    pub fn with_chain_block_time(mut self, time: u64) -> Self {
        self.chain_block_time = Some(time);
        self
    }

    pub fn with_flashbots_block_time(mut self, time: u64) -> Self {
        self.flashbots_block_time = Some(time);
        self
    }

    pub fn with_namespaces(mut self, namespaces: Option<String>) -> Self {
        self.namespaces = namespaces;
        self
    }

    pub fn with_extra_params(mut self, extra_params: Option<String>) -> Self {
        self.extra_params = extra_params;
        self
    }
}

#[derive(Default, Debug)]
pub struct OpRethConfig {
    auth_rpc_port: Option<u16>,
    jwt_secret_path: Option<PathBuf>,
    chain_config_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    http_port: Option<u16>,
    network_port: Option<u16>,
}

impl OpRethConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn auth_rpc_port(mut self, port: u16) -> Self {
        self.auth_rpc_port = Some(port);
        self
    }

    pub fn chain_config_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.chain_config_path = Some(path.into());
        self
    }

    pub fn data_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    pub fn network_port(mut self, port: u16) -> Self {
        self.network_port = Some(port);
        self
    }
}
