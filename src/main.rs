use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::{
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{rustls, TlsConnector};

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
    #[arg(short = 'c', long)]
    cert: Option<PathBuf>,

    #[arg(long, default_value = "/etc/ssl/cert.pem")]
    cafile: PathBuf,

    #[arg(required = true)]
    host: String,

    #[arg(default_value = "6667")]
    port: u16,
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
    write.write_all(pong).await
}

#[tokio::main]
async fn main() {
    let opt = Opt::parse();

    let stream = TcpStream::connect((opt.host.as_ref(), opt.port))
        .await
        .expect("failed to connect");

    if opt.tls {
        let config = rustls::ClientConfig::builder();
        let config = if opt.insecure {
            // rustls seems to make doing this intentionally annoying
            // https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html
            // https://users.rust-lang.org/t/rustls-connecting-without-certificate-in-local-network/83822
            todo!();
        } else {
            let mut root_cert_store = rustls::RootCertStore::empty();
            let mut pem = std::io::BufReader::new(
                std::fs::File::open(opt.cafile).expect("cannot open cafile"),
            );
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store.add(cert.unwrap()).unwrap();
            }
            config.with_root_certificates(root_cert_store)
        };
        let config = if let Some(_cert) = opt.cert {
            // with_client_auth_cert
            todo!();
        } else {
            config.with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(config));
        let domain = rustls_pki_types::ServerName::try_from(opt.host)
            .expect("invalid server name")
            .to_owned();
        let tlsstream = connector.connect(domain, stream).await.expect("failed to negotiate tls");
        handle_irc(tlsstream).await;
    } else {
        handle_irc(stream).await;
    }
}

async fn handle_irc(stream: impl io::AsyncReadExt + io::AsyncWriteExt) {
    let (read, mut write) = io::split(stream);
    let mut read = BufReader::new(read);
    let mut stdin = BufReader::new(io::stdin());
    let mut stdbuf = Vec::with_capacity(512);
    let mut ircbuf = Vec::with_capacity(512);

    loop {
        tokio::select! {
            Ok(len) = stdin.read_until(b'\n', &mut stdbuf) => {
                if len == 0 {
                    return;
                }

                trim_mut(&mut stdbuf);
                stdbuf.push(b'\r');
                stdbuf.push(b'\n');
                write.write_all(&stdbuf).await.expect("cannot send");

                stdbuf.clear();
            }
            Ok(len) = read.read_until(b'\n', &mut ircbuf) => {
                if len == 0 {
                    return;
                }

                if let Some(pong) = is_pong(&ircbuf) {
                    send_pong(&mut write, pong).await.expect("cannot send");
                }

                trim_mut(&mut ircbuf);
                ircbuf.push(b'\n');
                io::stdout().write_all(&ircbuf).await.expect("broken pipe");

                ircbuf.clear();
            }
        }
    }
}
