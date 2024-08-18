use clap::Parser;
use std::{io::Write, net::SocketAddr, path::PathBuf, process::exit, sync::Arc, time::Duration};
use tokio::{
    fs::File,
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::sleep,
};
use tokio_rustls::{
    rustls::{self, pki_types},
    TlsConnector,
};
use tokio_socks::tcp::Socks5Stream;

mod danger;

/// irc ping/ponger similar to ircdog
#[derive(Debug, Parser)]
struct Opt {
    /// connect over tls
    #[arg(short, long)]
    tls: bool,

    /// disable tls certificate verification
    #[arg(short = 'k', long)]
    insecure: bool,

    /// connect with a tls client certificate
    #[arg(short, long)]
    cert: Option<PathBuf>,

    #[arg(long, default_value = "/etc/ssl/cert.pem")]
    cafile: PathBuf,

    /// connect via socks5 proxy
    #[arg(short, long, value_name = "ADDRESS")]
    socks: Option<SocketAddr>,

    /// send pings after inactivity
    #[arg(short, long, value_name = "SECONDS")]
    ping: Option<u64>,

    /// quickly register with same nick/user/gecos
    #[arg(short, long, value_name = "NAME")]
    quickreg: Option<String>,

    /// register using lines from file
    #[arg(short, long, value_name = "FILE")]
    regfile: Option<PathBuf>,

    #[arg(required = true)]
    host: String,

    /// port defaults to 6667 or 6697 for tls
    port: Option<u16>,
}

fn trim_mut(buf: &mut Vec<u8>) {
    if let Some(last) = buf.last() {
        if b"\r\n".contains(last) {
            buf.pop();
            trim_mut(buf);
        }
    }
}

fn skip_word(buf: &[u8]) -> Option<&[u8]> {
    for (i, b) in buf.iter().enumerate() {
        if b == &b' ' {
            return Some(&buf[i + 1..]);
        }
    }
    None
}

fn is_pong(buf: &[u8]) -> Option<&[u8]> {
    if let Some(first) = buf.first() {
        if b"@:".contains(first) {
            return is_pong(skip_word(buf)?);
        }
        if buf.starts_with(b"PING ") {
            return Some(&buf[5..]);
        }
    }
    None
}

async fn send_pong(
    write: &mut io::WriteHalf<impl AsyncWriteExt>,
    pong: &[u8],
) -> Result<(), std::io::Error> {
    // FIXME: use write_all_vectored, instead of write_all
    // twice, once it becomes a thing
    // https://github.com/tokio-rs/tokio/issues/3679
    //write.write_all_vectored(&[b"PONG ", pong].map(IoSlice::new)).await?;
    write.write_all(b"PONG ").await?;
    write.write_all(pong).await?;
    write.flush().await
}

#[tokio::main]
async fn main() {
    let opt = Opt::parse();

    let port = if let Some(port) = opt.port {
        port
    } else if opt.tls {
        6697
    } else {
        6667
    };

    let target = (opt.host.as_ref(), port);

    if let Some(sock) = opt.socks {
        let stream = Socks5Stream::connect(sock, target)
            .await
            .expect("failed to sock");

        handle_tls(opt, stream).await;
    } else {
        let stream = TcpStream::connect(target).await.expect("failed to connect");

        handle_tls(opt, stream).await;
    }
}

async fn handle_tls<T>(opt: Opt, stream: T)
where
    T: io::AsyncReadExt + io::AsyncWriteExt + Unpin,
{
    if opt.tls {
        let config = rustls::ClientConfig::builder();
        let config = if opt.insecure {
            config
                .dangerous()
                .with_custom_certificate_verifier(danger::PhonyVerify::new(
                    rustls::crypto::ring::default_provider(),
                ))
        } else {
            let mut root_cert_store = rustls::RootCertStore::empty();
            let mut pem = std::io::BufReader::new(
                std::fs::File::open(&opt.cafile).expect("cannot open cafile"),
            );
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store.add(cert.unwrap()).unwrap();
            }
            config.with_root_certificates(root_cert_store)
        };
        let config = if let Some(ref cert) = opt.cert {
            use rustls_pemfile::Item;

            let mut pem = std::io::BufReader::new(
                std::fs::File::open(cert).expect("cannot open client cert"),
            );
            let mut certs = Vec::new();
            let mut keys: Vec<pki_types::PrivateKeyDer> = Vec::new();

            for c in rustls_pemfile::read_all(&mut pem) {
                match c.unwrap() {
                    Item::X509Certificate(crt) => certs.push(crt),
                    Item::Pkcs1Key(key) => keys.push(key.into()),
                    Item::Pkcs8Key(key) => keys.push(key.into()),
                    Item::Sec1Key(key) => keys.push(key.into()),
                    e => eprintln!("unknown item in pem: {:?}", e),
                }
            }

            config
                .with_client_auth_cert(certs, keys.pop().expect("no key found"))
                .expect("could not load client cert")
        } else {
            config.with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(config));
        let domain = pki_types::ServerName::try_from(opt.host.as_str())
            .expect("invalid server name")
            .to_owned();
        let tlsstream = connector
            .connect(domain, stream)
            .await
            .expect("failed to negotiate tls");
        handle_irc(opt, tlsstream).await;
    } else {
        handle_irc(opt, stream).await;
    }
}

async fn handle_irc<T>(opt: Opt, stream: T)
where
    T: io::AsyncReadExt + io::AsyncWriteExt,
{
    let pingdelay = Duration::from_secs(opt.ping.unwrap_or(0));
    let (read, mut write) = io::split(stream);
    let mut read = BufReader::new(read);
    let mut stdin = BufReader::new(io::stdin());
    let mut stdbuf = Vec::with_capacity(512);
    let mut ircbuf = Vec::with_capacity(512);

    if let Some(name) = opt.quickreg {
        let o = format!("NICK {0}\r\nUSER {0} 0 * :{}\r\n", name);
        write.write_all(o.as_bytes()).await.expect("cannot send");
        write.flush().await.expect("cannot send");
    }

    if let Some(path) = opt.regfile {
        let file = File::open(path).await.expect("bork regfile");
        let mut read = BufReader::new(file).lines();
        while let Some(mut line) = read.next_line().await.unwrap() {
            line.push('\r');
            line.push('\n');
            write.write_all(line.as_bytes()).await.expect("cannot send");
            write.flush().await.expect("cannot send");
        }
    }

    loop {
        tokio::select! {
            Ok(len) = stdin.read_until(b'\n', &mut stdbuf) => {
                if len == 0 {
                    exit(0);
                }

                trim_mut(&mut stdbuf);
                stdbuf.push(b'\r');
                stdbuf.push(b'\n');
                write.write_all(&stdbuf).await.expect("cannot send");
                write.flush().await.expect("cannot send");

                stdbuf.clear();
            }
            Ok(len) = read.read_until(b'\n', &mut ircbuf) => {
                if len == 0 {
                    exit(0);
                }

                if let Some(pong) = is_pong(&ircbuf) {
                    send_pong(&mut write, pong).await.expect("cannot send");
                }

                trim_mut(&mut ircbuf);
                ircbuf.push(b'\n');
                std::io::stdout().write_all(&ircbuf).expect("broken pipe");

                ircbuf.clear();
            }
            () = sleep(pingdelay), if opt.ping.is_some() => {
                write.write_all(b"PING :boop\r\n").await.expect("cannot send");
            }
        }
    }
}
