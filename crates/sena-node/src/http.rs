//! A minimal HTTP/1.1 transport: one request per connection.
//!
//! Each connection is read on a thread of its own, with a read timeout, and
//! its request is handed to the caller's loop through a channel; the reply is
//! written back and the connection closed. The node serves requests one at a
//! time on its own thread anyway, so nothing here needs to be concurrent
//! beyond reading and writing sockets.
//!
//! It replaces `tiny_http`, whose worker pool can strand a new connection
//! behind connections a browser holds open and idle: a wallet's requests then
//! hang with the node otherwise healthy.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// How long a client may take to send its request, or to read the reply.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection waits for the node to answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest request line plus headers accepted.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Connections served at once; more are refused with 503.
const MAX_CONNECTIONS: usize = 256;

/// A request's body, or why it was not read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Body {
    /// The body, as UTF-8.
    Text(String),
    /// `Content-Length` exceeded the limit; the body was not read.
    TooLarge(usize),
    /// The body could not be read, or is not UTF-8.
    Unreadable,
}

/// A request, as the caller sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpRequest {
    /// The method, upper case.
    pub method: String,
    /// Headers in the order sent.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Body,
    /// The client's address.
    pub remote: Option<IpAddr>,
}

impl HttpRequest {
    /// A header's value, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A reply.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Headers besides `Content-Length` and `Connection`.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: String,
}

/// A request awaiting its reply.
#[derive(Debug)]
pub struct Incoming {
    /// The request.
    pub request: HttpRequest,
    reply: Sender<HttpResponse>,
}

impl Incoming {
    /// Sends the reply; the connection is closed after it.
    pub fn respond(self, response: HttpResponse) {
        let _ = self.reply.send(response);
    }
}

/// A listening server.
#[derive(Debug)]
pub struct HttpServer {
    incoming: Receiver<Incoming>,
    stop: Arc<AtomicBool>,
}

impl HttpServer {
    /// Listens on `address`, reading bodies of at most `max_body` bytes.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the address cannot be bound.
    pub fn bind(address: impl ToSocketAddrs, max_body: usize) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        thread::spawn(move || accept_loop(&listener, &tx, &stopping, max_body));
        Ok(Self { incoming: rx, stop })
    }

    /// The next request, waiting at most `timeout`.
    #[must_use]
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Incoming> {
        self.incoming.recv_timeout(timeout).ok()
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn accept_loop(listener: &TcpListener, tx: &Sender<Incoming>, stop: &AtomicBool, max_body: usize) {
    let open = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if open.load(Ordering::Acquire) >= MAX_CONNECTIONS {
                    let _ = write_response(&stream, &unavailable());
                    continue;
                }
                open.fetch_add(1, Ordering::AcqRel);
                let tx = tx.clone();
                let open = Arc::clone(&open);
                thread::spawn(move || {
                    connection(&stream, Some(peer.ip()), &tx, max_body);
                    drop(stream);
                    open.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn unavailable() -> HttpResponse {
    HttpResponse {
        status: 503,
        headers: Vec::new(),
        body: String::new(),
    }
}

fn connection(stream: &TcpStream, remote: Option<IpAddr>, tx: &Sender<Incoming>, max_body: usize) {
    if stream.set_nonblocking(false).is_err()
        || stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let Some(request) = read_request(read_half, remote, max_body) else {
        let _ = write_response(
            stream,
            &HttpResponse {
                status: 400,
                headers: Vec::new(),
                body: String::new(),
            },
        );
        return;
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    if tx
        .send(Incoming {
            request,
            reply: reply_tx,
        })
        .is_err()
    {
        let _ = write_response(stream, &unavailable());
        return;
    }
    let response = reply_rx
        .recv_timeout(REPLY_TIMEOUT)
        .unwrap_or_else(|_| unavailable());
    let _ = write_response(stream, &response);
}

fn read_request(stream: TcpStream, remote: Option<IpAddr>, max_body: usize) -> Option<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut head = 0usize;
    let mut line = String::new();
    let mut next_line = |reader: &mut BufReader<TcpStream>| -> Option<String> {
        line.clear();
        let n = reader
            .by_ref()
            .take((MAX_HEAD_BYTES - head) as u64)
            .read_line(&mut line)
            .ok()?;
        head += n;
        if n == 0 || !line.ends_with('\n') {
            return None;
        }
        Some(line.trim_end_matches(['\r', '\n']).to_owned())
    };

    let request_line = next_line(&mut reader)?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_ascii_uppercase();
    let _target = parts.next()?;
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }

    let mut headers = Vec::new();
    loop {
        let l = next_line(&mut reader)?;
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':')?;
        headers.push((k.trim().to_owned(), v.trim().to_owned()));
    }

    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _): &&(String, String)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let body = if header("Transfer-Encoding").is_some() {
        // Chunked bodies are not supported; JSON-RPC clients send a length.
        Body::Unreadable
    } else {
        match header("Content-Length").map(|v| v.parse::<usize>()) {
            None => Body::Text(String::new()),
            Some(Err(_)) => Body::Unreadable,
            Some(Ok(len)) if len > max_body => Body::TooLarge(len),
            Some(Ok(len)) => {
                let mut buf = vec![0; len];
                match reader.read_exact(&mut buf) {
                    Ok(()) => String::from_utf8(buf).map_or(Body::Unreadable, Body::Text),
                    Err(_) => Body::Unreadable,
                }
            }
        }
    };
    Some(HttpRequest {
        method,
        headers,
        body,
        remote,
    })
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn write_response(mut stream: &TcpStream, r: &HttpResponse) -> std::io::Result<()> {
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        reason(r.status),
        r.body.len()
    );
    for (k, v) in &r.headers {
        // Header names and values come from this crate, never from a client,
        // but a stray line break would still split the response.
        if !k.contains(['\r', '\n']) && !v.contains(['\r', '\n']) {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out.push_str(&r.body);
    stream.write_all(out.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    fn server() -> (HttpServer, String) {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap().to_string();
        drop(probe);
        (HttpServer::bind(&addr, 64).unwrap(), addr)
    }

    fn exchange(addr: &str, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn answer(srv: &HttpServer, body: &str) -> HttpRequest {
        let i = srv.recv_timeout(Duration::from_secs(5)).expect("a request");
        let req = i.request.clone();
        i.respond(HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into(),
        });
        req
    }

    #[test]
    fn a_request_is_read_and_answered_and_the_connection_closed() {
        let (srv, addr) = server();
        let t = thread::spawn({
            let addr = addr.clone();
            move || {
                exchange(
                    &addr,
                    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n{\"a\"",
                )
            }
        });
        let req = answer(&srv, "{}");
        assert_eq!(req.method, "POST");
        assert_eq!(req.header("host"), Some("x"));
        assert_eq!(req.body, Body::Text("{\"a\"".into()));
        let out = t.join().unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(out.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn idle_connections_do_not_hold_up_others() {
        let (srv, addr) = server();
        let idle: Vec<_> = (0..8).map(|_| TcpStream::connect(&addr).unwrap()).collect();
        let clients: Vec<_> = (0..8)
            .map(|_| {
                let addr = addr.clone();
                thread::spawn(move || {
                    exchange(&addr, "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
                })
            })
            .collect();
        for _ in 0..8 {
            answer(&srv, "ok");
        }
        for c in clients {
            assert!(c.join().unwrap().ends_with("ok"));
        }
        drop(idle);
    }

    #[test]
    fn an_oversized_body_is_reported_unread() {
        let (srv, addr) = server();
        let t = thread::spawn(move || {
            exchange(&addr, "POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n")
        });
        assert_eq!(answer(&srv, "").body, Body::TooLarge(999_999));
        t.join().unwrap();
    }

    #[test]
    fn a_malformed_request_line_gets_400() {
        let (_srv, addr) = server();
        assert!(exchange(&addr, "nonsense\r\n\r\n").starts_with("HTTP/1.1 400"));
    }
}
