use std::{
    fs,
    io::{self, Read, Write, BufReader},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};
use rustls::{ClientConfig, ClientSession, Session};
use rustls::internal::pemfile;
use webpki::DNSNameRef;

struct MeteredStream {
    inner: TcpStream,
    bytes_read: usize,
    bytes_written: usize,
}

impl MeteredStream {
    fn new(inner: TcpStream) -> Self {
        Self { inner, bytes_read: 0, bytes_written: 0 }
    }
}

impl Read for MeteredStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n;
        Ok(n)
    }
}

impl Write for MeteredStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let n = self.inner.write_vectored(bufs)?;
        self.bytes_written += n;
        Ok(n)
    }
}

fn read_certs(path: &str) -> Vec<rustls::Certificate> {
    let f = fs::File::open(path).expect(&format!("cannot open {}", path));
    pemfile::certs(&mut BufReader::new(f)).expect("cannot parse certs")
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .parse_default_env()
        .init();

    let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4433".to_string());

    let use_rsa = std::env::var("USE_RSA").is_ok();
    let ca_path = if use_rsa { "test_rsa.crt" } else { "kem-ca.crt" };
    let mode = if use_rsa { "RSA (sin auth mutua)" } else { "KEMTLS (Kyber512, auth mutua)" };

    println!("🔧 Modo {}", mode);
    println!("📂 Cargando CA desde {}", ca_path);

    let ca_certs = read_certs(ca_path);
    println!("   ↳ {} certificados CA cargados", ca_certs.len());

    let mut cfg = ClientConfig::new();
    cfg.set_protocols(&[b"kemtls".to_vec()]);

    for cert in &ca_certs {
        cfg.root_store
            .add(cert)
            .expect("Error agregando cert CA al root store");
    }

    if !use_rsa {
        let client_certs = read_certs("client.crt");
        let client_key = {
            let f = fs::File::open("client.key").expect("cannot open client.key");
            let mut buf = BufReader::new(f);
            let keys = rustls::internal::pemfile::pkcs8_private_keys(&mut buf)
                .expect("cannot parse client.key");
            assert!(!keys.is_empty(), "no private key in client.key");
            keys.into_iter().next().unwrap()
        };
        cfg.set_single_client_cert(client_certs, client_key)
            .expect("Error configurando certificado de cliente");
        println!("🔐 Certificado de cliente KEM cargado");
    }

    if let Ok(server_cert_path) = std::env::var("KEMTLS_SERVER_CERT_PATH") {
        let server_certs = read_certs(&server_cert_path);
        println!("PDK: {} server certs pre-loaded for proactive encapsulation", server_certs.len());
        cfg.known_certificates = server_certs;
    }

    println!("✅ Root store configurado");

    let config = Arc::new(cfg);
    let dns_name = DNSNameRef::try_from_ascii_str("servername")
        .expect("invalid DNS name");

    println!("🔌 Conectando a {} ...", addr);
    let session_start = Instant::now();

    let stream = TcpStream::connect(&addr).expect("TCP connect failed");
    let tcp_connected_ns = session_start.elapsed().as_nanos();
    let tcp_connect_ms = tcp_connected_ns as f64 / 1_000_000.0;
    println!("   ↳ TCP conectado en {:.3}ms", tcp_connect_ms);

    let mut metered = MeteredStream::new(stream);
    let mut session = ClientSession::new(&config, dns_name);

    let mut eof = false;
    loop {
        while session.wants_write() {
            match session.write_tls(&mut metered) {
                Ok(_) => {}
                Err(e) => { eprintln!("write_tls error: {}", e); return; }
            }
        }

        if !session.is_handshaking() {
            break;
        }

        if session.wants_read() && !eof {
            match session.read_tls(&mut metered) {
                Ok(0) => { eof = true; }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => { eprintln!("read_tls error: {}", e); return; }
            }
        }

        if let Err(e) = session.process_new_packets() {
            eprintln!("TLS error: {:?}", e);
            return;
        }

        if eof {
            eprintln!("❌ EOF antes de completar handshake");
            return;
        }
    }

    // KEMTLS flips rustls into "traffic" mode before the peer's Finished is
    // processed, so we wait for one more TLS read/process cycle and only then
    // publish the client-side "session ready" mark.
    let bytes_read_before_ready = metered.bytes_read;
    metered
        .inner
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok();
    while metered.bytes_read == bytes_read_before_ready {
        match session.read_tls(&mut metered) {
            Ok(0) => break,
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                eprintln!("❌ Timeout esperando ServerFinished");
                return;
            }
            Err(e) => {
                eprintln!("read_tls error waiting for ServerFinished: {}", e);
                return;
            }
        }

        if let Err(e) = session.process_new_packets() {
            eprintln!("TLS error waiting for ServerFinished: {:?}", e);
            return;
        }
    }

    if eof {
        eprintln!("❌ EOF antes de recibir ServerFinished");
        return;
    }

    let session_ready_ns = session_start.elapsed().as_nanos();
    let protocol_handshake_ns = session_ready_ns.saturating_sub(tcp_connected_ns);
    let hs_bytes_written = metered.bytes_written;
    let hs_bytes_read = metered.bytes_read;
    let hs_bytes_total = hs_bytes_written + hs_bytes_read;
    let session_ready_ms = session_ready_ns as f64 / 1_000_000.0;
    let protocol_handshake_ms = protocol_handshake_ns as f64 / 1_000_000.0;

    println!("✅ Sesión KEMTLS lista en {:.3}ms", session_ready_ms);

    if let Ok(metrics_path) = std::env::var("KEMTLS_METRICS_JSON") {
        let json = format!(
            "{{\n  \"role\": \"client\",\n  \"tcp_connect_ms\": {:.3},\n  \"handshake_ms\": {:.3},\n  \"session_ready_ms\": {:.3},\n  \"session_start_ns\": 0,\n  \"tcp_connected_ns\": {},\n  \"session_ready_ns\": {},\n  \"handshake_time_ns\": {},\n  \"tcp_connect_time_ns\": {},\n  \"bytes_written\": {},\n  \"bytes_read\": {},\n  \"bytes_total\": {}\n}}\n",
            tcp_connect_ms,
            protocol_handshake_ms,
            session_ready_ms,
            tcp_connected_ns,
            session_ready_ns,
            protocol_handshake_ns,
            tcp_connected_ns,
            hs_bytes_written,
            hs_bytes_read,
            hs_bytes_total
        );
        std::fs::write(&metrics_path, json).ok();
    }

    session.write_all(b"HOLA KEMTLS\n").unwrap();
    while session.wants_write() {
        session.write_tls(&mut metered).ok();
    }

    metered.inner.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();
    let mut reply = vec![0u8; 256];
    let mut n = 0;
    while !eof {
        match session.read_tls(&mut metered) {
            Ok(0) => break,
            Ok(_) => {
                session.process_new_packets().ok();
                match session.read(&mut reply) {
                    Ok(k) if k > 0 => { n = k; break; }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut => break,
            Err(e) => { eprintln!("read error: {}", e); break; }
        }
    }
    if n > 0 {
        println!("📩 Respuesta: {}", String::from_utf8_lossy(&reply[..n]));
    }

    println!("🏁 Listo. Latencia total: {:.3}ms", session_start.elapsed().as_secs_f64() * 1000.0);
}
