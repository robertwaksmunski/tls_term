use docopt::Docopt;
use log::{debug, error};
use mimalloc::MiMalloc;
use mio;
use mio::net::{TcpListener, TcpStream};
use mio::{event, Events, Interest, Poll, Registry, Token};
use rustls;
use rustls_pemfile;
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::{self, IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;


// Use the Microsoft memory allocator
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Clone)]
enum ServerMode {
    Http,
    ForwardToLocalPort(u16),
}

// Keep the main state and config here
struct TlsTerm {
    server: TcpListener,
    connections: HashMap<Token, OpenConnection>,
    next: usize,
    tls: Arc<rustls::ServerConfig>,
    mode: ServerMode,
}

impl TlsTerm {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> Self {
        TlsTerm {
            server,
            connections: HashMap::new(),
            next: 2,
            tls: cfg,
            mode,
        }
    }

    fn accept(&mut self, registry: &Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {:?}", addr);

                    let tls_conn = rustls::ServerConnection::new(Arc::clone(&self.tls)).unwrap();
                    let mode = self.mode.clone();

                    let token = Token(self.next);
                    self.next += 1;

                    let mut connection = OpenConnection::new(socket, token, mode, tls_conn);
                    connection.register(registry);
                    self.connections.insert(token, connection);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    eprintln!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }

    fn event(&mut self, registry: &Registry, event: &event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

// Connection struct, kept in TlsTerm connections hash map
struct OpenConnection {
    socket: TcpStream,
    token: Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls: rustls::ServerConnection,
    back: Option<TcpStream>,
}

impl OpenConnection {
    fn new(
        socket: TcpStream,
        token: Token,
        mode: ServerMode,
        tls: rustls::ServerConnection,
    ) -> OpenConnection {
        let back = open_plain_backend(&mode);
        OpenConnection {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls,
            back,
        }
    }

    fn ready(&mut self, registry: &Registry, ev: &event::Event) {
        if ev.is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read();
        }

        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let _ = self.socket.shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(net::Shutdown::Both).unwrap();
        }
        self.back = None;
    }

    fn do_tls_read(&mut self) {
        match self.tls.read_tls(&mut self.socket) {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {:?}", err);
                self.closing = true;
                return;
            }
            Ok(0) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok(_) => {}
        };

        if let Err(err) = self.tls.process_new_packets() {
            error!("cannot process packet: {:?}", err);

            // last gasp write to send any alerts
            self.do_tls_write_and_handle_error();

            self.closing = true;
        }
    }

    fn try_plain_read(&mut self) {
        if let Ok(io_state) = self.tls.process_new_packets() {
            if io_state.plaintext_bytes_to_read() > 0 {
                let mut buf = Vec::new();
                buf.resize(io_state.plaintext_bytes_to_read(), 0u8);

                self.tls.reader().read(&mut buf).unwrap();

                debug!("plaintext read {:?}", buf.len());
                self.incoming_plaintext(&buf);
            }
        }
    }

    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // successful but empty read: EOF
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls.writer().write_all(&buf[..len]).unwrap();
            }
            None => {}
        };
    }

    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Http => {
                self.send_http_response();
            }
            ServerMode::ForwardToLocalPort(_) => {
                if self.back.as_mut().unwrap().write_all(buf).is_err() {
                    self.tls.send_close_notify();
                }
            }
        }
    }

    fn send_http_response(&mut self) {
        let details = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ntls_term\n\n\nProtocol: {:?}\nCipher: {:?}\nSNI Hostname: {:?}\r\n\r\n",
            &self.tls.protocol_version().unwrap(),
            &self.tls.negotiated_cipher_suite().unwrap(),
            &self.tls.sni_hostname()
        );
        self.tls.writer().write_all(&details.as_bytes()).unwrap();
        self.tls.send_close_notify();
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls.write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&mut self, registry: &Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(self.back.as_mut().unwrap(), self.token, Interest::READABLE)
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &Registry) {
        let event_set = self.event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &Registry) {
        registry.deregister(&mut self.socket).unwrap();

        if self.back.is_some() {
            registry.deregister(self.back.as_mut().unwrap()).unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> Interest {
        let wants_read = self.tls.wants_read();
        let wants_write = self.tls.wants_write();

        if wants_read && wants_write {
            Interest::READABLE | Interest::WRITABLE
        } else if wants_write {
            Interest::WRITABLE
        } else {
            Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_plain_backend(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::ForwardToLocalPort(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
}

fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

const USAGE: &'static str = "
Runs a TLS Terminator on :PORT.  The default PORT is 443.

`http' - server sends a HTTP response on each connection.

`forward' - server forwards plaintext to a connection made to
localhost:port.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tls_port --certs CERTFILE --key KEYFILE [options] http
  tls_port --certs CERTFILE --key KEYFILE [options] forward <port>
  tls_port (--version | -v)
  tls_port (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE     Read DER-encoded OCSP response from OCSPFILE and staple
                        to certificate.  Optional.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_http: bool,
    cmd_forward: bool,
    flag_port: Option<u16>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    arg_port: Option<u16>,
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let &Some(ref name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn make_config(args: &Args) -> Arc<rustls::ServerConfig> {
    let certs = load_certs(args.flag_certs.as_ref().expect("--certs option missing"));
    let privkey = load_private_key(args.flag_key.as_ref().expect("--key option missing"));
    let ocsp = load_ocsp(&args.flag_ocsp);

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
        .expect("bad certificates/private key");

    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(4096);
    config.ticketer = rustls::Ticketer::new().unwrap();

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect::<Vec<_>>();

    Arc::new(config)
}

fn main() {
    // Parse args
    let version = env!("CARGO_PKG_NAME").to_string() + " version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        args.flag_port.unwrap_or(443),
    );

    let config = make_config(&args);

    // Bind to socket and accept connections
    let mut listener_tcp = TcpListener::bind(addr).expect("cannot listen on TCP port");

    const TCP: Token = Token(0);

    let mut poll = Poll::new().unwrap();

    poll.registry()
        .register(&mut listener_tcp, TCP, Interest::READABLE)
        .unwrap();


    let mode = if args.cmd_http {
        ServerMode::Http
    } else {
        ServerMode::ForwardToLocalPort(args.arg_port.expect("port required"))
    };

    let mut tls_term = TlsTerm::new(listener_tcp, mode, config);


    let mut events = Events::with_capacity(256);

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                TCP => {
                    tls_term
                        .accept(poll.registry())
                        .expect("error accepting socket");
                },
                _ => tls_term.event(poll.registry(), &event),
            }
        }
    }
}
