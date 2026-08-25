//! The half a browser cannot do: accepting sessions, and having a certificate.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::{Link, LinkError};

/// A self-signed certificate and the hash a client must pin to accept it.
///
/// # Why this exists rather than "just turn verification off"
///
/// A browser will not talk WebTransport to an unverified server at all, so
/// there is no off switch to reach for. What it offers instead is
/// `serverCertificateHashes`: pin this exact certificate by its SHA-256. That
/// is a genuinely reasonable answer for a self-hosted instance whose operator
/// has no CA certificate — and it comes with a condition worth knowing before
/// building on it, which is that browsers cap the validity of a pinned
/// certificate at about two weeks. A deployment therefore needs rotation, and
/// clients need to be told the new hash. That is not a prototype problem, but
/// it is a deployment problem, and pretending otherwise here would just move
/// the discovery later.
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// SHA-256 of the DER certificate — what the client pins.
    pub hash: Vec<u8>,
}

impl Identity {
    /// Generate one for `names` (`"localhost"`, an IP, whatever the client
    /// will dial).
    pub fn self_signed(names: &[&str]) -> Result<Identity, LinkError> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let cert = rcgen::generate_simple_self_signed(names)
            .map_err(|e| LinkError::Transport(format!("certificate: {e}")))?;
        let der = CertificateDer::from(cert.cert);
        let hash = Sha256::digest(der.as_ref()).to_vec();
        let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .map_err(|e| LinkError::Transport(format!("key: {e}")))?;
        Ok(Identity { chain: vec![der], key, hash })
    }

    /// The hash as hex, which is how it travels to a client — in a config
    /// file, a URL, or the same API response that already tells the client
    /// which node to dial.
    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Accepts incoming links. Native only — a browser can dial a WebTransport
/// session but cannot host one.
pub struct Listener {
    inner: web_transport_quinn::Server,
}

impl Listener {
    pub fn bind(addr: std::net::SocketAddr, identity: &Identity) -> Result<Listener, LinkError> {
        let inner = web_transport_quinn::ServerBuilder::new()
            .with_addr(addr)
            .with_certificate(identity.chain.clone(), identity.key.clone_key())
            .map_err(|e| LinkError::Transport(format!("listen on {addr}: {e}")))?;
        Ok(Listener { inner })
    }

    /// The address actually bound. Needed because binding to port 0 — which is
    /// how anything that runs concurrently should bind — leaves the caller not
    /// knowing where to dial.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, LinkError> {
        self.inner.local_addr().map_err(|e| LinkError::Transport(e.to_string()))
    }

    /// Wait for the next session. `None` once the endpoint is closed.
    pub async fn accept(&mut self) -> Option<Link> {
        let request = self.inner.accept().await?;
        // The request carries the URL path, which is where room and identity
        // will live — the same place the WebSocket carried them as a query
        // string. Nothing reads it yet.
        match request.ok().await {
            Ok(session) => Some(Link::from_session(session.into())),
            Err(_) => None,
        }
    }
}
