use clap::Parser;
use irc_connect::{
    tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
        RootCertStore,
    },
    Stream,
};
use std::{
    collections::BTreeSet, io::Write, net::SocketAddr, path::PathBuf, process::exit, time::Duration,
};
use tokio::{
    fs::File,
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::lookup_host,
    time::sleep,
};

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

    /// commands or numerics to avoid printing
    ///
    /// may be specified multiple times to ignore more
    #[arg(short, long)]
    ignore: Vec<Vec<u8>>,

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

fn split_word(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    for (i, b) in buf.iter().enumerate() {
        if b == &b' ' {
            return Some((&buf[..i], &buf[i + 1..]));
        }
    }
    None
}

#[test]
fn check_split_word() {
    assert_eq!(split_word(b"nospaces"), None);
    assert_eq!(
        split_word(b"yip yap yop"),
        Some((b"yip".as_ref(), b"yap yop".as_ref()))
    );
}

fn split_cmd(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(first) = buf.first() {
        if b"@:".contains(first) {
            return split_cmd(split_word(buf)?.1);
        }
        return split_word(buf);
    }
    None
}

#[test]
fn check_split_cmd() {
    assert_eq!(
        split_cmd(b":yip yap yop"),
        Some((b"yap".as_ref(), b"yop".as_ref()))
    );
    assert_eq!(
        split_cmd(b"@yip :yap yop yote"),
        Some((b"yop".as_ref(), b"yote".as_ref()))
    );
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

    let target = lookup_host((opt.host.as_ref(), port))
        .await
        .expect("looking up host")
        .next()
        .unwrap();

    let stream = Stream::new_tcp(&target);

    let stream = if let Some(addr) = opt.socks {
        stream.socks5(addr)
    } else {
        stream
    };

    let stream = if opt.tls {
        let domain = ServerName::try_from(opt.host.as_str())
            .expect("invalid server name")
            .to_owned();
        if opt.insecure {
            stream.tls_danger_insecure(domain)
        } else {
            let mut root_cert_store = RootCertStore::empty();
            let mut pem = std::io::BufReader::new(
                std::fs::File::open(&opt.cafile).expect("cannot open cafile"),
            );
            for cert in rustls_pemfile::certs(&mut pem) {
                root_cert_store.add(cert.unwrap()).unwrap();
            }
            stream.tls_with_root(domain, root_cert_store)
        }
    } else {
        stream
    };

    let stream = if let Some(ref cert) = opt.cert {
        let certs = CertificateDer::pem_file_iter(cert)
            .expect("opening client cert")
            .collect::<Result<Vec<_>, _>>()
            .expect("parsing client cert");
        let key = PrivateKeyDer::from_pem_file(cert).expect("opening client cert key");
        stream.client_cert(certs, key)
    } else {
        stream
    };

    let stream = stream.connect().await.expect("connecting");

    let pingdelay = Duration::from_secs(opt.ping.unwrap_or(0));
    let (read, mut write) = io::split(stream);
    let mut read = BufReader::new(read);
    let mut stdin = BufReader::new(io::stdin());
    let mut stdbuf = Vec::with_capacity(512);
    let mut ircbuf = Vec::with_capacity(512);
    let ignores = BTreeSet::from_iter(opt.ignore);

    if let Some(ref name) = opt.quickreg {
        let o = format!("NICK {name}\r\nUSER {name} 0 * :{name}\r\n");
        write.write_all(o.as_bytes()).await.expect("cannot send");
        write.flush().await.expect("cannot send");
    }

    if let Some(ref path) = opt.regfile {
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

                if process_incoming(&ignores, &mut write, &ircbuf).await {
                    trim_mut(&mut ircbuf);
                    ircbuf.push(b'\n');
                    std::io::stdout().write_all(&ircbuf).expect("broken pipe");
                }

                ircbuf.clear();
            }
            () = sleep(pingdelay), if opt.ping.is_some() => {
                write.write_all(b"PING :boop\r\n").await.expect("cannot send");
            }
        }
    }
}

async fn process_incoming(
    ignores: &BTreeSet<Vec<u8>>,
    write: &mut io::WriteHalf<impl AsyncWriteExt>,
    buf: &[u8],
) -> bool {
    if let Some((cmd, rest)) = split_cmd(buf) {
        if b"PING" == cmd {
            send_pong(write, rest).await.expect("cannot send");
        }
        if ignores.contains(cmd) {
            return false;
        }
    }
    true
}
