#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tropic01-example-rpi is only built for Linux targets; skipping");
}
