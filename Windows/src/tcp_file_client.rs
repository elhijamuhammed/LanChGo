use std::{
    fs::{OpenOptions},
    io::{self, BufWriter, Read, Write},
    net::{IpAddr, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

pub fn download_offer( sender_ip: IpAddr, tcp_port: u16, offer_id: [u8; 16], save_path: PathBuf, mut on_progress: impl FnMut(u64, u64), ) -> io::Result<()> {
    // connect (small retry helps on Wi-Fi)
    let mut stream = {
        let mut last_err: Option<io::Error> = None;
        let addr = (sender_ip, tcp_port);
        let mut s_opt = None;

        for _ in 0..20 {
            match TcpStream::connect(addr) {
                Ok(s) => {
                    s_opt = Some(s);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        s_opt.ok_or_else(|| {
            last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "connect failed"))
        })?
    };

    // Timeouts: allow Wi-Fi stalls
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
    let _ = stream.set_nodelay(true); // header request benefits a bit

    // ---- request
    stream.write_all(b"FOFR")?;
    stream.write_all(&[crate::file_transfer_protocol::FILE_PROTOCOL_VERSION])?;
    stream.write_all(&offer_id)?;
    // No need to flush here; TCP will send. (Flushing can add stalls on some stacks.)

    // ---- response header
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != b"FOFS" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad FOFS magic"));
    }

    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver)?;
    if ver[0] != crate::file_transfer_protocol::FILE_PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Protocol version mismatch",
        ));
    }

    let mut size_bytes = [0u8; 8];
    stream.read_exact(&mut size_bytes)?;
    let total = u64::from_le_bytes(size_bytes);

    // ---- download into .part file (atomic publish)
    let part_path = save_path.with_extension("part");

    // Use OpenOptions so you can tweak behavior later
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&part_path)?;

    // Optional: pre-allocate space to reduce fragmentation (usually helps)
    // If you find this slow on some disks, you can remove it.
    let _ = file.set_len(total);

    // Big buffered writer for fewer syscalls
    let mut out = BufWriter::with_capacity(1024 * 1024, file);

    // Bigger read buffer (1MB)
    let mut buf = vec![0u8; 1024 * 1024];

    let mut got = 0u64;

    // Throttle progress updates (UI can be the bottleneck)
    let mut last_ui = Instant::now();
    const UI_INTERVAL: Duration = Duration::from_millis(150);

    let res: io::Result<()> = (|| {
        while got < total {
            let want = (total - got).min(buf.len() as u64) as usize;
            let n = stream.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed early",
                ));
            }

            out.write_all(&buf[..n])?;
            got += n as u64;

            if last_ui.elapsed() >= UI_INTERVAL || got == total {
                last_ui = Instant::now();
                on_progress(got, total);
            }
        }

        // Guard: must match exactly
        if got != total {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("incomplete file: got {} of {}", got, total),
            ));
        }

        out.flush()?; // ensure buffered bytes hit the OS

        // ⚠️ sync_all is very slow on Windows; only enable if you *need* durability guarantees.
        // If you want it as an option:
        // out.get_ref().sync_all()?;

        // Atomic “publish”
        std::fs::rename(&part_path, &save_path)?;
        Ok(())
    })();

    if res.is_err() {
        let _ = std::fs::remove_file(&part_path);
    }

    res
}
