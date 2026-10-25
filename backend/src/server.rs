//! TCP accept loop. Unlike `axum::serve` it can abort a connection without answering, which
//! is how the service hides itself from scanners and invalid requests.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

use crate::app::{DropConnection, RemoteAddr};

#[derive(Debug)]
struct Dropped;

impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection dropped on purpose")
    }
}

impl std::error::Error for Dropped {}

/// Binds `[::]:port` dual-stack (what Node's `listen(port)` does), falling back to IPv4.
pub fn bind(port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let try_bind = |addr: SocketAddr| -> std::io::Result<TcpListener> {
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        if addr.is_ipv6() {
            socket.set_only_v6(false)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        socket.listen(1024)?;
        TcpListener::from_std(socket.into())
    };

    try_bind(SocketAddr::from(([0u16; 8], port)))
        .or_else(|_| try_bind(SocketAddr::from(([0, 0, 0, 0], port))))
}

/// Simultaneous open connections; beyond this, new connections wait in the kernel backlog.
pub const MAX_CONNECTIONS: usize = 10_000;

pub async fn serve<S>(listener: TcpListener, router: S, shutdown: impl Future<Output = ()>)
where
    S: tower::Service<Request<Body>, Response = axum::response::Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    serve_with_limit(listener, router, shutdown, MAX_CONNECTIONS).await;
}

pub async fn serve_with_limit<S>(
    listener: TcpListener,
    router: S,
    shutdown: impl Future<Output = ()>,
    max_connections: usize,
) where
    S: tower::Service<Request<Body>, Response = axum::response::Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    let graceful = GracefulShutdown::new();
    let permits = Arc::new(Semaphore::new(max_connections));
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            p = permits.clone().acquire_owned() => p.expect("semaphore is never closed"),
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);

        let router = router.clone();
        let service = service_fn(move |req: Request<Incoming>| {
            let router = router.clone();
            async move {
                let mut req = req.map(Body::new);
                req.extensions_mut().insert(RemoteAddr(peer));
                let resp = match router.oneshot(req).await {
                    Ok(resp) => resp,
                    Err(infallible) => match infallible {},
                };
                if resp.extensions().get::<DropConnection>().is_some() {
                    return Err(Dropped);
                }
                Ok::<_, Dropped>(resp)
            }
        });

        // HTTP/1.1 only (as the Node version): the service sits behind a reverse proxy.
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(30))
            .serve_connection(TokioIo::new(stream), service);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _permit = permit;
            // Errors here are deliberate drops or client disconnects.
            let _ = conn.await;
        });
    }

    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(Duration::from_secs(10)) => {
            tracing::warn!("forcing shutdown with connections still open");
        }
    }
}
