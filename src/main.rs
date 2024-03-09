use clap::Parser;
use tokio::{
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

#[derive(Debug, Parser)]
struct Opt {
    #[arg(required = true)]
    destination: String,
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
    write: &mut io::WriteHalf<TcpStream>,
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

    let stream = TcpStream::connect(opt.destination)
        .await
        .expect("failed to connect");

    let (read, mut write) = io::split(stream);
    let mut read = BufReader::new(read);
    let mut stdin = BufReader::new(io::stdin());
    let mut stdbuf: Vec<u8> = Vec::with_capacity(8192 + 512);
    let mut ircbuf: Vec<u8> = Vec::with_capacity(8192 + 512);

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
