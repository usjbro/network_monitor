mod parse;
mod l7;

use tokio::net::TcpListener;

fn detect_interface() -> String {
    match pcap::Device::lookup() {
        Ok(Some(device)) => device.name,
        Ok(None) => panic!("no capture-capable network interface found"),
        Err(e) => panic!("failed to look up default capture device: {e}"),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let interface = detect_interface();
    println!("capture-agent: using interface {interface}");

    let listener = TcpListener::bind("127.0.0.1:9990").await?;
    println!("capture-agent: listening on 127.0.0.1:9990");

    loop {
        let (socket, _addr) = listener.accept().await?;
        drop(socket);
    }
}
