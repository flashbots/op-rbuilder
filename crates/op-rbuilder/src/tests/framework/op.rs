use std::{
    fs::File,
    future::Future,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use reth_cli_commands::NodeCommand;
use reth_db::init_db;
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_optimism_cli::chainspec::OpChainSpecParser;
use reth_tasks::TaskManager;
use std::time::Duration;
use tokio::time::sleep;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt;

use crate::{
    args::OpRbuilderArgs,
    builders::{FlashblocksBuilder, StandardBuilder},
    launcher::{BuilderLauncher, NodeContext},
};
use clap::Parser;

use super::{
    service::{self, Service},
    DEFAULT_JWT_TOKEN,
};

#[derive(Default, Debug, Clone)]
pub struct OpRbuilderConfig {
    auth_rpc_port: Option<u16>,
    jwt_secret_path: Option<PathBuf>,
    chain_config_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    http_port: Option<u16>,
    network_port: Option<u16>,
    builder_private_key: Option<String>,
    flashblocks_port: Option<u16>,
    chain_block_time: Option<u64>,
    flashbots_block_time: Option<u64>,
    with_revert_protection: Option<bool>,
    namespaces: Option<String>,
    extra_params: Option<String>,
    log_file: PathBuf,
}

impl OpRbuilderConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn log_file(mut self, path: PathBuf) -> Self {
        self.log_file = path;
        self
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

    pub fn with_flashblocks_port(mut self, port: u16) -> Self {
        self.flashblocks_port = Some(port);
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

pub struct OpRbuilder {
    pub _handle: NodeContext,
    pub _tracing_guard: DefaultGuard,
    pub _task_manager: TaskManager,
}

impl OpRbuilderConfig {
    pub async fn start(self) -> eyre::Result<OpRbuilder> {
        // This creates a custom log subscriber only for this task
        let file = File::create(self.log_file.clone()).unwrap();

        let subscriber = fmt::Subscriber::builder()
            .with_writer(file)
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);

        // We are reusing the same commands generated for running the op-rbuilder binary.
        // But, there are two main differences we have to account for:
        // - We are parsing directly on top of the "node" command, so we need to skip that first arg
        // - We have to preppend the 'op-rbuilder' binary name to the args, otherwise the parser will fail
        let cmd = self.command();
        let cmd_args = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        let mut args = vec!["op-rbuilder".to_string()]; // add op-rbuilder
        args.extend(cmd_args.clone().into_iter().skip(1)); // skip 'node'

        let command =
            NodeCommand::<OpChainSpecParser, OpRbuilderArgs>::try_parse_from(args).unwrap();

        // This is extracted from the "NodeCommand" execute function.
        let NodeCommand::<OpChainSpecParser, OpRbuilderArgs> {
            datadir,
            config,
            chain,
            metrics,
            instance,
            with_unused_ports: _,
            network,
            rpc,
            txpool,
            builder,
            debug,
            db,
            dev,
            pruning,
            ext,
            engine,
        } = command;

        // set up node config
        let node_config = NodeConfig {
            datadir,
            config,
            chain,
            metrics,
            instance,
            network,
            rpc,
            txpool,
            builder,
            debug,
            db,
            dev,
            pruning,
            engine,
        };

        let tasks = TaskManager::current();
        let exec = tasks.executor();

        // Using a real database for the builder. There is a function to use a memory database called 'testing_node'
        // which might be useful in the future. However, It uses a concrete database implementation and I could not
        // figure out how to make it work with the main launcher.
        let data_dir = node_config.datadir();
        let db_path = data_dir.db();
        let database =
            Arc::new(init_db(db_path.clone(), command.db.database_args())?.with_metrics());

        let builder = NodeBuilder::new(node_config)
            .with_database(database)
            .with_launch_context(exec.clone());

        let is_builder_mode = ext.flashblocks.enabled;
        let handle = match is_builder_mode {
            false => {
                let launcher = BuilderLauncher::<StandardBuilder>::new();
                launcher.launch(builder, ext).await?
            }
            true => {
                let launcher = BuilderLauncher::<FlashblocksBuilder>::new();
                launcher.launch(builder, ext).await?
            }
        };

        // We need to keep both the handle and the task manager in scope otherwise the node will exit
        Ok(OpRbuilder {
            _handle: handle,
            _tracing_guard: guard,
            _task_manager: tasks,
        })
    }
}

impl Service for OpRbuilderConfig {
    fn command(&self) -> Command {
        let mut bin_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        bin_path.push("../../target/debug/op-rbuilder");

        let mut cmd = Command::new(bin_path);
        let jwt_path = get_or_create_jwt_path(self.jwt_secret_path.as_ref());

        cmd.arg("node")
            .arg("--authrpc.port")
            .arg(
                self.auth_rpc_port
                    .expect("auth_rpc_port not set")
                    .to_string(),
            )
            .arg("--authrpc.jwtsecret")
            .arg(
                jwt_path
                    .to_str()
                    .expect("Failed to convert jwt_path to string"),
            )
            .arg("--chain")
            .arg(
                self.chain_config_path
                    .as_ref()
                    .expect("chain_config_path not set"),
            )
            .arg("--datadir")
            .arg(self.data_dir.as_ref().expect("data_dir not set"))
            .arg("--disable-discovery")
            //.arg("--color")
            //.arg("never")
            .arg("--builder.log-pool-transactions")
            .arg("--port")
            .arg(self.network_port.expect("network_port not set").to_string())
            .arg("--ipcdisable");
        // .arg("-vvvv");

        if let Some(revert_protection) = self.with_revert_protection {
            if revert_protection {
                cmd.arg("--builder.enable-revert-protection");
            }
        }

        if let Some(builder_private_key) = &self.builder_private_key {
            cmd.arg("--rollup.builder-secret-key")
                .arg(builder_private_key);
        }

        if let Some(http_port) = self.http_port {
            cmd.arg("--http")
                .arg("--http.port")
                .arg(http_port.to_string());
        }

        if let Some(flashblocks_port) = &self.flashblocks_port {
            cmd.arg("--flashblocks.enabled");
            cmd.arg("--flashblocks.addr").arg("127.0.0.1");
            cmd.arg("--flashblocks.port")
                .arg(flashblocks_port.to_string());
        }

        if let Some(chain_block_time) = self.chain_block_time {
            cmd.arg("--rollup.chain-block-time")
                .arg(chain_block_time.to_string());
        }

        if let Some(flashbots_block_time) = self.flashbots_block_time {
            cmd.arg("--flashblocks.block-time")
                .arg(flashbots_block_time.to_string());
        }

        if let Some(namespaces) = &self.namespaces {
            cmd.arg("--http.api").arg(namespaces);
        }

        if let Some(extra_params) = &self.extra_params {
            cmd.args(extra_params.split_ascii_whitespace());
        }

        cmd
    }

    #[allow(clippy::manual_async_fn)]
    fn ready(&self, log_path: &Path) -> impl Future<Output = Result<(), service::Error>> + Send {
        async move {
            poll_logs(
                log_path,
                "Starting consensus engine",
                Duration::from_millis(100),
                Duration::from_secs(60),
            )
            .await
        }
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

impl Service for OpRethConfig {
    fn command(&self) -> Command {
        let bin_path = PathBuf::from("op-reth");

        let mut cmd = Command::new(bin_path);
        let jwt_path = get_or_create_jwt_path(self.jwt_secret_path.as_ref());

        cmd.arg("node")
            .arg("--authrpc.port")
            .arg(
                self.auth_rpc_port
                    .expect("auth_rpc_port not set")
                    .to_string(),
            )
            .arg("--authrpc.jwtsecret")
            .arg(
                jwt_path
                    .to_str()
                    .expect("Failed to convert jwt_path to string"),
            )
            .arg("--chain")
            .arg(
                self.chain_config_path
                    .as_ref()
                    .expect("chain_config_path not set"),
            )
            .arg("--datadir")
            .arg(self.data_dir.as_ref().expect("data_dir not set"))
            .arg("--disable-discovery")
            .arg("--color")
            .arg("never")
            .arg("--port")
            .arg(self.network_port.expect("network_port not set").to_string())
            .arg("--ipcdisable");

        if let Some(http_port) = self.http_port {
            cmd.arg("--http")
                .arg("--http.port")
                .arg(http_port.to_string());
        }

        cmd
    }

    #[allow(clippy::manual_async_fn)]
    fn ready(&self, log_path: &Path) -> impl Future<Output = Result<(), service::Error>> + Send {
        async move {
            poll_logs(
                log_path,
                "Starting consensus engine",
                Duration::from_millis(100),
                Duration::from_secs(60),
            )
            .await
        }
    }
}

fn get_or_create_jwt_path(jwt_path: Option<&PathBuf>) -> PathBuf {
    jwt_path.cloned().unwrap_or_else(|| {
        let tmp_dir = std::env::temp_dir();
        let jwt_path = tmp_dir.join("jwt.hex");
        std::fs::write(&jwt_path, DEFAULT_JWT_TOKEN).expect("Failed to write JWT secret file");
        jwt_path
    })
}

/// Helper function to poll logs periodically
pub async fn poll_logs(
    log_path: &Path,
    pattern: &str,
    interval: Duration,
    timeout: Duration,
) -> Result<(), service::Error> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(service::Error::Spawn(ErrorKind::TimedOut));
        }

        let mut file = File::open(log_path).map_err(|_| service::Error::Logs)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|_| service::Error::Logs)?;

        if contents.contains(pattern) {
            return Ok(());
        }

        sleep(interval).await;
    }
}
