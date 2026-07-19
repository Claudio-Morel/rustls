use rustls::internal::pemfile;
use rustls::{AllowAnyAuthenticatedClient, RootCertStore};
use rustls::{ServerConfig, ServerSession, Session};
use std::{
    fs,
    io::{self, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
};

// The client and server run in different network namespaces but share the
// host's monotonic clock.  `Instant::elapsed()` is process-local evidence and
// cannot be compared across the two processes, so the benchmark records the
// absolute CLOCK_MONOTONIC value at each protocol boundary.
fn monotonic_ns() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[cfg(target_os = "linux")]
const CLOCK_MONOTONIC: i32 = 1;

#[cfg(target_os = "linux")]
extern "C" {
    fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
}

// Keep the FFI declaration's type in the same scope on Linux without pulling
// an additional libc dependency into this standalone benchmark crate.
#[cfg(target_os = "linux")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn write_metrics_atomic(path: &Path, payload: &str) -> io::Result<()> {
    let tmp_path = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    let result = (|| {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn read_certs(path: &str) -> Vec<rustls::Certificate> {
    let f = fs::File::open(path).expect(&format!("cannot open {}", path));
    pemfile::certs(&mut BufReader::new(f)).expect("cannot parse certs")
}

fn read_private_key(path: &str) -> rustls::PrivateKey {
    let f = fs::File::open(path).expect(&format!("cannot open {}", path));
    let mut buf = BufReader::new(f);
    let keys = pemfile::pkcs8_private_keys(&mut buf).expect("cannot parse key");
    assert!(!keys.is_empty(), "no private key found in {}", path);
    keys.into_iter().next().unwrap()
}

fn handle_client(
    mut stream: TcpStream,
    config: Arc<ServerConfig>,
    crypto_variant: String,
    metrics_path: Option<PathBuf>,
) {
    let peer = stream.peer_addr().unwrap();
    let connection_accepted_ns = monotonic_ns();
    println!("⚡ Conexión de {}", peer);

    let mut session = ServerSession::new(&config);
    let mut buf = [0u8; 8192];
    let mut eof = false;

    let mut session_ready_written = false;
    loop {
        // 1. Leer UN registro TLS por iteración: process+write antes de releer
        //    evita el deadlock donde ambos lados esperan datos del otro.
        if session.wants_read() && !eof {
            match session.read_tls(&mut stream) {
                Ok(0) => {
                    eof = true;
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("read_tls error from {}: {}", peer, e);
                    return;
                }
            }
        }

        // 2. Procesar paquetes recibidos
        if let Err(e) = session.process_new_packets() {
            eprintln!("TLS protocol error from {}: {:?}", peer, e);
            while session.wants_write() {
                let _ = session.write_tls(&mut stream);
            }
            return;
        }

        // Check the state immediately after process_new_packets().  This is
        // the first observation that rustls has left the handshake after
        // validating ClientFinished; doing it after draining wants_write()
        // could include the emission of a NewSessionTicket in the PDK timing
        // boundary.
        if !session.is_handshaking() && !session_ready_written {
            let session_ready_ns = monotonic_ns();
            if let Some(path) = metrics_path.as_ref() {
                let handshake_time_ns = session_ready_ns.saturating_sub(connection_accepted_ns);
                let payload = format!(
                    "{{\n  \"role\": \"server\",\n  \"crypto_variant\": \"{}\",\n  \"clock_source\": \"CLOCK_MONOTONIC\",\n  \"clock_domain\": \"host-monotonic\",\n  \"connection_accepted_ns\": {},\n  \"session_ready_ns\": {},\n  \"handshake_time_ns\": {},\n  \"session_ready_event\": \"ClientFinished validated\"\n}}\n",
                    crypto_variant,
                    connection_accepted_ns,
                    session_ready_ns,
                    handshake_time_ns,
                );
                if let Err(error) = write_metrics_atomic(path, &payload) {
                    eprintln!(
                        "server metrics write failed for {}: {}",
                        path.display(),
                        error
                    );
                }
            }
            println!(
                "SERVER SESSION READY: ClientFinished validated at {} ns",
                session_ready_ns
            );
            session_ready_written = true;
        }

        // 3. Enviar datos TLS pendientes
        while session.wants_write() {
            match session.write_tls(&mut stream) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("write_tls error from {}: {}", peer, e);
                    return;
                }
            }
        }

        // 4. Si todavía está en handshake, volver a leer
        if session.is_handshaking() {
            if eof {
                eprintln!("❌ EOF durante handshake con {}", peer);
                return;
            }
            continue;
        }

        // rustls only leaves the handshake state after validating the peer's
        // Finished.  In KEMTLS-PDK this is the required bilateral boundary:
        // the server has validated ClientFinished, even though the client may
        // already have installed its local traffic keys.
        // 5. Handshake completado — leer datos de aplicación
        match session.read(&mut buf) {
            Ok(0) => {
                if eof {
                    break;
                }
            }
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]);
                println!("📩 Recibido de {}: {}", peer, msg.trim());
                let reply = format!("KEMTLS-OK: {}", msg.trim());
                session.write_all(reply.as_bytes()).ok();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("read error from {}: {}", peer, e);
                break;
            }
        }

        while session.wants_write() {
            session.write_tls(&mut stream).ok();
        }

        if eof {
            break;
        }

        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
    }

    println!("🔌 Conexión cerrada con {}", peer);
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let use_rsa = std::env::var("USE_RSA").is_ok();
    let (cert_path, key_path, client_ca_path) = if use_rsa {
        println!("🔧 Modo RSA (prueba, sin auth mutua)");
        ("test_server.crt", "test_server.key", None)
    } else {
        println!("🔧 Modo KEMTLS (Kyber512, auth mutua)");
        ("kem.chain.crt", "kem.key", Some("client-ca.crt"))
    };

    let certs = read_certs(cert_path);
    println!("📜 {} certificados cargados", certs.len());
    let key = read_private_key(key_path);
    println!("🔑 Llave privada leída ({} bytes DER)", key.0.len());

    let mut cfg = if let Some(ca_path) = client_ca_path {
        let ca_certs = read_certs(ca_path);
        let mut root_store = RootCertStore::empty();
        for cert in &ca_certs {
            root_store
                .add(cert)
                .expect("Error agregando client CA al root store");
        }
        println!(
            "🔐 Auth mutua habilitada: {} CA(s) de clientes",
            ca_certs.len()
        );
        ServerConfig::new(AllowAnyAuthenticatedClient::new(root_store))
    } else {
        ServerConfig::new(rustls::NoClientAuth::new())
    };
    cfg.set_single_cert(certs, key)
        .expect("Error configurando certificado KEMTLS");
    cfg.set_protocols(&[b"kemtls".to_vec()]);

    println!("✅ Configuración KEMTLS lista");

    let config = Arc::new(cfg);
    let crypto_variant =
        std::env::var("KEMTLS_CRYPTO_VARIANT").unwrap_or_else(|_| "unknown".to_string());
    let metrics_path = std::env::var_os("KEMTLS_SERVER_METRICS_JSON").map(PathBuf::from);
    let listener = TcpListener::bind("0.0.0.0:4433").expect("bind failed");
    println!("🔮 Servidor escuchando en 0.0.0.0:4433");
    println!("   (Esperando conexiones KEMTLS...)");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let cfg = Arc::clone(&config);
                let variant = crypto_variant.clone();
                let report_path = metrics_path.clone();
                std::thread::spawn(move || handle_client(s, cfg, variant, report_path));
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}
