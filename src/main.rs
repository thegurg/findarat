use clap::Parser;

use findarat::cli::{self, Cli};
use findarat::error::exit_code_for;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = cli::run(cli).await {
        eprintln!("error: {error:#}");
        std::process::exit(i32::from(exit_code_for(&error)));
    }
}
