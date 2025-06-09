use op_rbuilder::{
    args::{Cli, CliExt},
    launcher::launch,
};

fn main() -> eyre::Result<()> {
    let cli = Cli::parsed();
    launch(cli)
}
