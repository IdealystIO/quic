//! The half a browser cannot do: accepting sessions, and having a certificate.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// How long a generated certificate is valid.
///
/// Thirteen days, because browsers cap a *pinned* certificate at fourteen and
/// the margin covers a machine whose clock is a little fast. This is the number
/// that makes rotation a deployment requirement rather than a nicety — see
/// [`Identity`].
const VALID_DAYS: u64 = 13;
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
        let mut params = rcgen::CertificateParams::new(names)
            .map_err(|e| LinkError::Transport(format!("certificate: {e}")))?;

        // The validity window is NOT a detail. A browser accepts a pinned
        // certificate only if it expires within about two weeks — the trade it
        // demands for skipping a CA — and `rcgen`'s default runs to the year
        // 4096. With that default Chromium answers "Opening handshake failed",
        // which names neither certificates nor validity and reads exactly like
        // a blocked port.
        //
        // A day of backdating absorbs clock skew between the two machines,
        // which is otherwise a certificate that is not yet valid.
        let now = std::time::SystemTime::now();
        params.not_before = (now - std::time::Duration::from_secs(24 * 60 * 60)).into();
        params.not_after = (now + std::time::Duration::from_secs(VALID_DAYS * 24 * 60 * 60)).into();

        // ECDSA P-256, which is what browsers require of a pinned certificate.
        // `rcgen`'s default already, named explicitly because the failure if it
        // ever changed is the same unreadable handshake error as above.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| LinkError::Transport(format!("key: {e}")))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| LinkError::Transport(format!("certificate: {e}")))?;

        let der = CertificateDer::from(cert);
        let hash = Sha256::digest(der.as_ref()).to_vec();
        let key = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|e| LinkError::Transport(format!("key: {e}")))?;
        Ok(Identity { chain: vec![der], key, hash })
    }

    /// Load a CA-issued certificate chain and its private key, both PEM — what
    /// certbot writes as `fullchain.pem` and `privkey.pem`.
    ///
    /// A client dials this with system roots (no hash), so none of the pinning
    /// conditions above apply: no fortnight cap, nothing to rotate on restart.
    /// [`hash`](Identity::hash) is still the leaf's, for a client that pins
    /// anyway.
    pub fn from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<Identity, LinkError> {
        use rustls_pki_types::pem::PemObject;
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LinkError::Transport(format!("certificate chain: {e}")))?;
        let leaf = chain
            .first()
            .ok_or_else(|| LinkError::Transport("certificate chain: no certificates in it".into()))?;
        let hash = Sha256::digest(leaf.as_ref()).to_vec();
        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|e| LinkError::Transport(format!("private key: {e}")))?;
        Ok(Identity { chain, key, hash })
    }

    /// The hash as hex, which is how it travels to a client — in a config
    /// file, a URL, or the same API response that already tells the client
    /// which node to dial.
    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_hash;

    #[test]
    fn a_generated_certificate_expires_inside_the_window_browsers_allow() {
        // The number browsers enforce is fourteen days, and exceeding it fails
        // as "Opening handshake failed" — words that name neither certificates
        // nor validity. This is the assertion that keeps that from coming back.
        assert!(VALID_DAYS < 14, "a pinned certificate must expire within a fortnight");
        assert!(VALID_DAYS > 1, "and be worth generating");
    }

    #[test]
    fn an_identity_publishes_the_hash_of_the_certificate_it_actually_has() {
        let id = Identity::self_signed(&["127.0.0.1"]).expect("generates");
        let hex = id.hash_hex();
        assert_eq!(hex.len(), 64, "sha-256 as hex");
        assert_eq!(parse_hash(&hex).as_deref(), Some(id.hash.as_slice()));
        assert_eq!(
            id.hash,
            Sha256::digest(id.chain[0].as_ref()).to_vec(),
            "the published hash is of the certificate that is served",
        );
    }

    #[test]
    fn a_pem_identity_round_trips_and_hashes_its_leaf() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["example.test".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let id = Identity::from_pem(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes())
            .expect("loads");
        assert_eq!(id.chain.len(), 1);
        assert_eq!(id.chain[0].as_ref(), cert.der().as_ref());
        assert_eq!(id.hash, Sha256::digest(cert.der().as_ref()).to_vec());
    }

    #[test]
    fn a_pem_with_no_certificate_is_refused() {
        assert!(Identity::from_pem(b"", b"").is_err());
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

    /// Wait for the next connect request. `None` once the endpoint is closed.
    ///
    /// A request is not yet a session: it carries the URL the client dialled,
    /// and it can be [refused](Request::refuse) with a status the client can
    /// read. That ordering matters — it is the WebTransport equivalent of
    /// checking a ticket before the upgrade, rather than opening a connection
    /// and killing it for no stated reason.
    pub async fn accept(&mut self) -> Option<Request> {
        Some(Request { inner: self.inner.accept().await? })
    }
}

/// A client asking to open a session, before it has been allowed to.
pub struct Request {
    inner: web_transport_quinn::Request,
}

impl Request {
    /// The URL the client dialled, path and query included.
    ///
    /// This is where room, participant id and ticket live — the same place the
    /// WebSocket carried them.
    pub fn url(&self) -> String {
        self.inner.connect().url.to_string()
    }

    /// Where the client is dialling from, for logs.
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.inner.conn().remote_address()
    }

    /// Allow it, and get the link.
    pub async fn accept(self) -> Result<Link, LinkError> {
        match self.inner.ok().await {
            Ok(session) => Ok(Link::from_session(session.into())),
            Err(e) => Err(LinkError::Transport(format!("accept: {e}"))),
        }
    }

    /// Refuse it with an HTTP status, which the browser surfaces to the page.
    ///
    /// An unknown status code is sent as 403: refusing is already the
    /// answer, and failing to refuse because the code was wrong would leave
    /// the request hanging.
    pub async fn refuse(self, status: u16) {
        let status = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::FORBIDDEN);
        let _ = self.inner.reject(status).await;
    }
}
