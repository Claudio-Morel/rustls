use std::{
    fs,
    io::{self, Read, Write, BufReader},
    net::{TcpListener, TcpStream},
    sync::Arc,
};
use rustls::{ServerConfig, ServerSession, Session};
use rustls::internal::pemfile;
use rustls::{AllowAnyAuthenticatedClient, RootCertStore};

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

fn handle_client(mut stream: TcpStream, config: Arc<ServerConfig>) {
    let peer = stream.peer_addr().unwrap();
    println!("⚡ Conexión de {}", peer);

    let mut session = ServerSession::new(&config);
    let mut buf = [0u8; 8192];
    let mut eof = false;

    loop {
        // 1. Leer UN registro TLS por iteración: process+write antes de releer
        //    evita el deadlock donde ambos lados esperan datos del otro.
        if session.wants_read() && !eof {
            match session.read_tls(&mut stream) {
                Ok(0) => { eof = true; }
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

        // 5. Handshake completado — leer datos de aplicación
        match session.read(&mut buf) {
            Ok(0) => {
                if eof { break; }
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

        if eof { break; }

        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
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
            root_store.add(cert).expect("Error agregando client CA al root store");
        }
        println!("🔐 Auth mutua habilitada: {} CA(s) de clientes", ca_certs.len());
        ServerConfig::new(AllowAnyAuthenticatedClient::new(root_store))
    } else {
        ServerConfig::new(rustls::NoClientAuth::new())
    };
    cfg.set_single_cert(certs, key)
        .expect("Error configurando certificado KEMTLS");
    cfg.set_protocols(&[b"kemtls".to_vec()]);

    println!("✅ Configuración KEMTLS lista");

    let config = Arc::new(cfg);
    let listener = TcpListener::bind("0.0.0.0:4433").expect("bind failed");
    println!("🔮 Servidor escuchando en 0.0.0.0:4433");
    println!("   (Esperando conexiones KEMTLS...)");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let cfg = Arc::clone(&config);
                std::thread::spawn(move || handle_client(s, cfg));
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}
