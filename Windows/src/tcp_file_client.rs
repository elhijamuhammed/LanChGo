use std::{
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

use crate::file_transfer_protocol::FILE_PROTOCOL_VERSION;

const FOFR_MAGIC: &[u8; 4] = b"FOFR";
const FOFS_MAGIC: &[u8; 4] = b"FOFS";

pub fn download_offer(
    sender_ip: IpAddr,
    tcp_port: u16,
    offer_id: [u8; 16],
    save_path: PathBuf,
    mut on_progress: impl FnMut(u64, u64),
) -> io::Result<()> {
    // connect (small retry helps on Wi-Fi)
    let mut stream = {
        let mut last_err: Option<io::Error> = None;
        let addr = (sender_ip, tcp_port);
        let mut s_opt = None;

        for _ in 0..20 {
            match TcpStream::connect(addr) {
                Ok(s) => { s_opt = Some(s); break; }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        s_opt.ok_or_else(|| last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "connect failed")) )?
    };

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // request
    stream.write_all(FOFR_MAGIC)?;
    stream.write_all(&[FILE_PROTOCOL_VERSION])?;
    stream.write_all(&offer_id)?;
    stream.flush()?;

    // response header
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != FOFS_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad FOFS magic"));
    }

    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver)?;
    if ver[0] != FILE_PROTOCOL_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Protocol version mismatch"));
    }

    let mut size_bytes = [0u8; 8];
    stream.read_exact(&mut size_bytes)?;
    let total = u64::from_le_bytes(size_bytes);

    // receive
    let mut out = File::create(&save_path)?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0u64;

    while got < total {
        let want = (total - got).min(buf.len() as u64) as usize;
        let n = stream.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed early"));
        }
        out.write_all(&buf[..n])?;
        got += n as u64;
        on_progress(got, total);
    }

    out.flush()?;
    Ok(())
}
