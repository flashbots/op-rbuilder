use op_rbuilder::args::{Cli, CliExt};
use op_rbuilder::launcher::launch;

fn main() -> eyre::Result<()> {
    let cli = Cli::parsed();
    launch(cli)
}
