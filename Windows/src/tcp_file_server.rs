use std::{ fs::File, io::{self, BufRead, BufReader, Read, Write}, net::{TcpListener, TcpStream}, sync::{Arc, Mutex}, thread, time::Duration, };
use crate::file_transfer_protocol::{ hex_to_offer_id, LocalFileOffer, OfferRegistry, FILE_PROTOCOL_VERSION, };

const FOFR_MAGIC: &[u8; 4] = b"FOFR"; // Windows request
const FOFS_MAGIC: &[u8; 4] = b"FOFS"; // Windows stream response

// Tunables
const FILE_BUF_SIZE: usize = 1024 * 1024; // 1 MB
const READ_TIMEOUT_SECS: u64 = 20;
const WRITE_TIMEOUT_SECS: u64 = 120;

// ===================== Server =====================

pub fn start_file_server( registry: Arc<Mutex<OfferRegistry>>, port: u16, ) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;

    let handle = thread::spawn(move || {
        //println!("[TCP] File server listening on 0.0.0.0:{port}");

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    //println!("[TCP] accepted from {:?}", stream.peer_addr().ok());
                    let reg = Arc::clone(&registry);

                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream, reg) {
                            //println!("[TCP] handler error: {e}");
                        }
                    });
                }
                Err(e) => {
                    //println!("[TCP] accept error: {e}");
                }
            }
        }
    });

    Ok(handle)
}

// ===================== Dispatcher =====================

fn handle_client(mut stream: TcpStream, registry: Arc<Mutex<OfferRegistry>>) -> io::Result<()> {
    //println!("[TCP] client connected {:?}", stream.peer_addr().ok());

    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECS)));

    // Peek first 4 bytes to determine protocol
    let mut first4 = [0u8; 4];
    let n = stream.peek(&mut first4)?;

    if n >= 4 && &first4 == FOFR_MAGIC {
        //println!("[TCP] protocol = WINDOWS (FOFR)");
        handle_client_windows(stream, registry)
    } else {
        //println!("[TCP] protocol = MOBILE");
        handle_client_mobile(stream, registry)
    }
}

// ===================== Windows protocol =====================
// FOFR + ver + offer_id(16)
// FOFS + ver + size(u64)
// raw bytes

fn handle_client_windows(mut stream: TcpStream, registry: Arc<Mutex<OfferRegistry>>) -> io::Result<()> {
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != FOFR_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad FOFR magic"));
    }

    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver)?;
    if ver[0] != FILE_PROTOCOL_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Protocol version mismatch"));
    }

    let mut offer_id = [0u8; 16];
    stream.read_exact(&mut offer_id)?;

    let local: LocalFileOffer = {
        let reg = registry.lock().unwrap();
        reg.get(&offer_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Offer not found"))?
    };

    //println!( "[TCP][WIN] serving {} ({} bytes)", local.path.display(), local.size );

    stream.write_all(FOFS_MAGIC)?;
    stream.write_all(&[FILE_PROTOCOL_VERSION])?;
    stream.write_all(&local.size.to_le_bytes())?;
    stream.flush()?;

    let file = File::open(&local.path)?;
    let mut reader = BufReader::with_capacity(FILE_BUF_SIZE, file);
    let mut buf = vec![0u8; FILE_BUF_SIZE];

    let mut sent: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n])?;
        sent += n as u64;
    }

    stream.flush()?;
    //println!("[TCP][WIN] done sent={sent}");

    Ok(())
}

// ===================== Mobile protocol =====================
// "<offer_id_hex>\n"
// "OK\n"
// raw bytes until EOF

fn handle_client_mobile(stream: TcpStream, registry: Arc<Mutex<OfferRegistry>>) -> io::Result<()> {
    let mut reader = BufReader::new(stream);

    // Read offer_id_hex line
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let offer_id_hex = line.trim();

    //println!("[TCP][MOBILE] request id={offer_id_hex}");

    if offer_id_hex.len() != 32 {
        reader.get_mut().write_all(b"ERR\n")?;
        reader.get_mut().flush()?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid offer_id_hex"));
    }

    let offer_id = hex_to_offer_id(offer_id_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Bad hex offer id"))?;

    let local: LocalFileOffer = {
        let reg = registry.lock().unwrap();
        reg.get(&offer_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Offer not found"))?
    };

    //println!( "[TCP][MOBILE] serving {} ({} bytes)", local.path.display(), local.size );

    // Mobile ACK
    reader.get_mut().write_all(b"OK\n")?;
    reader.get_mut().flush()?;

    let file = File::open(&local.path)?;
    let mut file_reader = BufReader::with_capacity(FILE_BUF_SIZE, file);
    let mut buf = vec![0u8; FILE_BUF_SIZE];

    let mut sent: u64 = 0;
    loop {
        let n = file_reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        reader.get_mut().write_all(&buf[..n])?;
        sent += n as u64;
    }

    reader.get_mut().flush()?;
    //println!("[TCP][MOBILE] done sent={sent}");

    Ok(())
}
