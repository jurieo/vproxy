//! Future types.

use std::{
    future::Future,
    io,
    io::{Error, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{Timeout, timeout},
};
use tokio_rustls::{Accept, TlsAcceptor, server::TlsStream};

use super::RustlsConfig;

pin_project! {
    /// Future type for [`RustlsAcceptor`](crate::tls_rustls::RustlsAcceptor).
    pub struct RustlsAcceptorFuture<F, I> {
        #[pin]
        inner: AcceptFuture<F, I>,
        config: RustlsConfig,
    }
}

impl<F, I> RustlsAcceptorFuture<F, I> {
    pub(crate) fn new(future: F, config: RustlsConfig, handshake_timeout: Duration) -> Self {
        let inner = AcceptFuture::Inner {
            future,
            handshake_timeout,
        };
        Self { inner, config }
    }
}

pin_project! {
    #[project = AcceptFutureProj]
    enum AcceptFuture<F, I> {
        Inner {
            #[pin]
            future: F,
            handshake_timeout: Duration,
        },
        Accept {
            #[pin]
            future: Timeout<Accept<I>>,
        },
    }
}

impl<F, I> Future for RustlsAcceptorFuture<F, I>
where
    F: Future<Output = io::Result<I>>,
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<I>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.inner.as_mut().project() {
                AcceptFutureProj::Inner {
                    future,
                    handshake_timeout,
                } => match future.poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        let server_config = this.config.get_inner();
                        let acceptor = TlsAcceptor::from(server_config);
                        let future = acceptor.accept(stream);
                        let handshake_timeout = *handshake_timeout;

                        this.inner.set(AcceptFuture::Accept {
                            future: timeout(handshake_timeout, future),
                        });
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                },
                AcceptFutureProj::Accept { future } => match future.poll(cx) {
                    Poll::Ready(Ok(Ok(stream))) => {
                        return Poll::Ready(Ok(stream));
                    }
                    Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(e)),
                    Poll::Ready(Err(timeout)) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::TimedOut, timeout)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}
