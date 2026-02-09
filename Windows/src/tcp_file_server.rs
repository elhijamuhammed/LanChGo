use std::{ fs::File, io::{self, BufReader, Read, Write}, net::{TcpListener, TcpStream}, sync::{Arc, Mutex}, thread, time::{Duration}, };
use crate::file_transfer_protocol::{ /* offer_id_to_hex, */ LocalFileOffer, OfferRegistry, FILE_PROTOCOL_VERSION, };

const FOFR_MAGIC: &[u8; 4] = b"FOFR"; // request
const FOFS_MAGIC: &[u8; 4] = b"FOFS"; // stream response
// Tune these if you want
const FILE_BUF_SIZE: usize = 1024 * 1024; // 1MB
const READ_TIMEOUT_SECS: u64 = 20;
const WRITE_TIMEOUT_SECS: u64 = 120;

pub fn start_file_server( registry: Arc<Mutex<OfferRegistry>>,port: u16, ) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;

    let handle = thread::spawn(move || {
        //println!("[TCP] File server listening on 0.0.0.0:{}", port);

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    //let addr = stream.peer_addr().ok();
                    //println!("[TCP] accepted connection from {:?}", addr);

                    let reg = Arc::clone(&registry);
                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream, reg) {
                            //println!("[TCP] handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    //println!("[TCP] accept error: {}", e);
                    // keep listening
                }
            }
        }
    });

    Ok(handle)
}

fn handle_client(mut stream: TcpStream, registry: Arc<Mutex<OfferRegistry>>) -> io::Result<()> {
    //let peer = stream.peer_addr().ok();
    //println!("[TCP] client connected {:?}", peer);

    // QoL settings
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECS)));

    // ---- Read FOFR header: magic(4) + ver(1) + offer_id(16)
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != FOFR_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad FOFR magic"));
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
    //let offer_hex = offer_id_to_hex(&offer_id);
    //println!("[TCP] request offer_id={}", offer_hex);

    // ---- Lookup local offer
    let local: LocalFileOffer = {
        let reg = registry.lock().unwrap();
        reg.get(&offer_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Offer not found"))?
    };

    //println!("[TCP] serving path={} size={}",local.path.display(),local.size);

    // ---- Send FOFS response header: magic(4) + ver(1) + size(u64 LE)
    stream.write_all(FOFS_MAGIC)?;
    stream.write_all(&[FILE_PROTOCOL_VERSION])?;
    stream.write_all(&local.size.to_le_bytes())?;
    stream.flush()?; // push header quickly

    // ---- Stream file bytes (fast path)
    let file = File::open(&local.path)?;
    let mut reader = BufReader::with_capacity(FILE_BUF_SIZE, file);

    let mut buf = vec![0u8; FILE_BUF_SIZE];
    let mut sent: u64 = 0;

    //let start = Instant::now();

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n])?;
        sent += n as u64;
    }

    stream.flush()?;

    //let secs = start.elapsed().as_secs_f64().max(0.000_001);
    //let mbps = (sent as f64 / (1024.0 * 1024.0)) / secs;

    //println!("[TCP] done offer_id={} sent={} expected={} speed={:.2} MB/s peer={:?}",offer_hex, sent, local.size, mbps, peer);

    Ok(())
}
