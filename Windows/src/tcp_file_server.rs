use std::{ fs::File, io::{self, Read, Write}, net::{TcpListener, TcpStream}, sync::{Arc, Mutex}, thread, time::Duration, };

use crate::file_transfer_protocol::{
    offer_id_to_hex, LocalFileOffer, OfferRegistry, FILE_PROTOCOL_VERSION,
};

const FOFR_MAGIC: &[u8; 4] = b"FOFR"; // request
const FOFS_MAGIC: &[u8; 4] = b"FOFS"; // stream response

pub fn start_file_server(
    registry: Arc<Mutex<OfferRegistry>>,
    port: u16,
) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;

    let handle = thread::spawn(move || {
        println!("[TCP] File server listening on 0.0.0.0:{}", port);

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    let addr = stream.peer_addr().ok();
                    println!("[TCP] accepted connection from {:?}", addr);

                    let reg = Arc::clone(&registry);
                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream, reg) {
                            println!("[TCP] handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    println!("[TCP] accept error: {}", e);
                    // keep listening
                }
            }
        }
    });

    Ok(handle)
}

fn handle_client(mut stream: TcpStream, registry: Arc<Mutex<OfferRegistry>>) -> io::Result<()> {
    println!("[TCP] client connected");

    // Optional quality-of-life settings
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    // ---- Read FOFR header
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != FOFR_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Bad FOFR magic",
        ));
    }

    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver)?;
    if ver[0] != FILE_PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Protocol version mismatch",
        ));
    }

    let mut offer_id = [0u8; 16];
    stream.read_exact(&mut offer_id)?;
    let offer_hex = offer_id_to_hex(&offer_id);
    println!("[TCP] request offer_id={}", offer_hex);

    // ---- Lookup local offer
    let local: LocalFileOffer = {
        let reg = registry.lock().unwrap();
        reg.get(&offer_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Offer not found"))?
    };

    println!(
        "[TCP] serving path={} size={}",
        local.path.display(),
        local.size
    );

    // ---- Send FOFS response header
    stream.write_all(FOFS_MAGIC)?;
    stream.write_all(&[FILE_PROTOCOL_VERSION])?;
    stream.write_all(&local.size.to_le_bytes())?;
    stream.flush()?; // push header quickly

    // ---- Stream file bytes
    let mut file = File::open(&local.path)?;
    let mut buf = vec![0u8; 256 * 1024];

    let mut sent: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n])?;
        sent += n as u64;
    }
    stream.flush()?;

    println!(
        "[TCP] done offer_id={} sent={} expected={}",
        offer_hex, sent, local.size
    );

    Ok(())
}
