//! Async pure-Rust ACME (RFC 8555) client.

#![warn(unreachable_pub)]
#![warn(missing_docs)]

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::de::DeserializeOwned;
use serde::Serialize;

mod types;
pub use types::{
    AccountCredentials, Authorization, AuthorizationStatus, Challenge, ChallengeType, Error,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderState, OrderStatus, Problem,
};
use types::{
    DirectoryUrls, Empty, FinalizeRequest, Header, JoseJson, Jwk, KeyOrKeyId, SigningAlgorithm,
};
pub use ureq;
use ureq::Response;

/// An ACME order as described in RFC 8555 (section 7.1.3)
///
/// An order is created from an [`Account`] by calling [`Account::new_order()`]. The `Order`
/// type represents the stable identity of an order, while the [`Order::state()`] method
/// gives you access to the current state of the order according to the server.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
pub struct Order {
    account: Arc<AccountInner>,
    nonce: Option<String>,
    order_url: String,
}

impl Order {
    /// Retrieve the authorizations for this order
    ///
    /// An order will contain one authorization to complete per identifier in the order.
    /// After creating an order, you'll need to retrieve the authorizations so that
    /// you can set up a challenge response for each authorization.
    ///
    /// For each authorization, you'll need to:
    ///
    /// * Select which [`ChallengeType`] you want to complete
    /// * Create a [`KeyAuthorization`] for that [`Challenge`]
    /// * Call [`Order::set_challenge_ready()`] for that challenge
    ///
    /// After the challenges have been set up, check the [`Order::state()`] to see
    /// if the order is ready to be finalized (or becomes invalid). Once it is
    /// ready, call `Order::finalize()` to get the certificate.
    pub fn authorizations(&mut self, authz_urls: &[String]) -> Result<Vec<Authorization>, Error> {
        let mut authorizations = Vec::with_capacity(authz_urls.len());
        for url in authz_urls {
            authorizations.push(self.account.get(&mut self.nonce, url)?);
        }
        Ok(authorizations)
    }

    /// Create a [`KeyAuthorization`] for the given [`Challenge`]
    ///
    /// Signs the challenge's token with the account's private key and use the
    /// value from [`KeyAuthorization::as_str()`] as the challenge response.
    pub fn key_authorization(&self, challenge: &Challenge) -> KeyAuthorization {
        KeyAuthorization::new(challenge, &self.account.key)
    }

    /// Request a certificate from the given Certificate Signing Request (CSR)
    ///
    /// Creating a CSR is outside of the scope of small-acme. Make sure you pass in a
    /// DER representation of the CSR in `csr_der` and the [`OrderState::finalize`] URL
    /// in `finalize_url`. The resulting `String` will contain the PEM-encoded certificate chain.
    pub fn finalize(&mut self, csr_der: &[u8], finalize_url: &str) -> Result<String, Error> {
        let rsp = self.account.post(
            Some(&FinalizeRequest::new(csr_der)),
            self.nonce.take(),
            finalize_url,
        )?;

        self.nonce = nonce_from_response(&rsp);
        let state = Problem::check::<OrderState>(rsp)?;

        let cert_url = match state.certificate {
            Some(url) => url,
            None => return Err(Error::Str("no certificate URL")),
        };

        let rsp = self
            .account
            .post(None::<&Empty>, self.nonce.take(), &cert_url)?;

        self.nonce = nonce_from_response(&rsp);
        let body = Problem::from_response(rsp)?;
        Ok(
            String::from_utf8(body.to_vec())
                .map_err(|_| "unable to decode certificate as UTF-8")?,
        )
    }

    /// Notify the server that the given challenge is ready to be completed
    ///
    /// `challenge_url` should be the `Challenge::url` field.
    pub fn set_challenge_ready(&mut self, challenge_url: &str) -> Result<(), Error> {
        let rsp = self
            .account
            .post(Some(&Empty {}), self.nonce.take(), challenge_url)?;

        self.nonce = nonce_from_response(&rsp);
        let _ = Problem::check::<Challenge>(rsp)?;
        Ok(())
    }

    /// Get the current state of the given challenge
    pub fn challenge(&mut self, challenge_url: &str) -> Result<Challenge, Error> {
        self.account.get(&mut self.nonce, challenge_url)
    }

    /// Get the current state of the order
    pub fn state(&mut self) -> Result<OrderState, Error> {
        self.account.get(&mut self.nonce, &self.order_url)
    }
}

/// An ACME account as described in RFC 8555 (section 7.1.2)
///
/// Create an [`Account`] with [`Account::create()`] or restore it from serialized data
/// by passing deserialized [`AccountCredentials`] to [`Account::from_credentials()`].
///
/// The [`Account`] type is cheap to clone.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2>
#[derive(Clone)]
pub struct Account {
    inner: Arc<AccountInner>,
}

impl Account {
    /// Restore an existing account from the given credentials
    ///
    /// The [`AccountCredentials`] type is opaque, but supports deserialization.
    pub fn from_credentials(credentials: AccountCredentials<'_>) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(AccountInner::from_credentials(credentials)?),
        })
    }

    /// Create a new account on the `server_url` with the information in [`NewAccount`]
    pub fn create(account: &NewAccount<'_>, server_url: &str) -> Result<Account, Error> {
        let client = Client::new(server_url)?;
        let key = Key::generate()?;
        let rsp = client.post(Some(account), None, &key, &client.urls.new_account)?;

        let account_url = rsp.header("location").map(ToOwned::to_owned);

        // The response redirects, we don't need the body
        let _ = Problem::from_response(rsp)?;
        Ok(Self {
            inner: Arc::new(AccountInner {
                client,
                key,
                id: account_url.ok_or("failed to get account URL")?,
            }),
        })
    }

    /// Create a new order based on the given [`NewOrder`]
    ///
    /// Returns both an [`Order`] instance and the initial [`OrderState`].
    pub fn new_order(&self, order: &NewOrder) -> Result<(Order, OrderState), Error> {
        let rsp = self
            .inner
            .post(Some(order), None, &self.inner.client.urls.new_order)?;

        let nonce = nonce_from_response(&rsp);
        let order_url = rsp.header("location").map(ToOwned::to_owned);

        let status = Problem::check(rsp)?;
        Ok((
            Order {
                account: self.inner.clone(),
                nonce,
                order_url: order_url.ok_or("no order URL found")?,
            },
            status,
        ))
    }

    /// Get the account's credentials, which can be serialized
    ///
    /// Pass the credentials to [`Account::from_credentials`] to regain access to the `Account`.
    pub fn credentials(&self) -> AccountCredentials<'_> {
        self.inner.credentials()
    }
}

struct AccountInner {
    client: Client,
    key: Key,
    id: String,
}

impl AccountInner {
    fn from_credentials(credentials: AccountCredentials<'_>) -> Result<Self, Error> {
        Ok(Self {
            key: Key::from_pkcs8_der(BASE64_URL_SAFE_NO_PAD.decode(&credentials.key_pkcs8)?)?,
            client: Client {
                client: client(),
                urls: credentials.urls.into_owned(),
            },
            id: credentials.id.into_owned(),
        })
    }

    fn get<T: DeserializeOwned>(&self, nonce: &mut Option<String>, url: &str) -> Result<T, Error> {
        let rsp = self.post(None::<&Empty>, nonce.take(), url)?;
        *nonce = nonce_from_response(&rsp);
        Problem::check(rsp)
    }

    fn post(
        &self,
        payload: Option<&impl Serialize>,
        nonce: Option<String>,
        url: &str,
    ) -> Result<Response, Error> {
        self.client.post(payload, nonce, self, url)
    }

    fn credentials(&self) -> AccountCredentials<'_> {
        AccountCredentials {
            id: Cow::Borrowed(&self.id),
            key_pkcs8: BASE64_URL_SAFE_NO_PAD.encode(&self.key.pkcs8_der),
            urls: Cow::Borrowed(&self.client.urls),
        }
    }
}

impl Signer for AccountInner {
    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: &'n str, url: &'u str) -> Header<'n> {
        Header {
            alg: self.key.signing_algorithm,
            key: KeyOrKeyId::KeyId(&self.id),
            nonce,
            url,
        }
    }

    fn key(&self) -> &Key {
        &self.key
    }
}

#[derive(Debug)]
struct Client {
    client: ureq::Agent,
    urls: DirectoryUrls,
}

impl Client {
    fn new(server_url: &str) -> Result<Self, Error> {
        let client = client();
        let rsp = client.get(server_url).call()?;
        let urls = rsp.into_json()?;
        Ok(Client { client, urls })
    }

    fn post(
        &self,
        payload: Option<&impl Serialize>,
        mut nonce: Option<String>,
        signer: &impl Signer,
        url: &str,
    ) -> Result<Response, Error> {
        if nonce.is_none() {
            let rsp = self
                .client
                .request("HEAD", &self.urls.new_nonce)
                .send_string("")?;
            nonce = nonce_from_response(&rsp);
        };

        let nonce = nonce.ok_or("no nonce found")?;
        let rsp = self
            .client
            .request("POST", url)
            .set("content-type", JOSE_JSON)
            .send_json(signer.signed_json(payload, &nonce, url)?)?;

        Ok(rsp)
    }
}

struct Key {
    rng: SystemRandom,
    signing_algorithm: SigningAlgorithm,
    inner: EcdsaKeyPair,
    pkcs8_der: Vec<u8>,
    thumb: String,
}

impl Key {
    fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())?;
        let thumb = BASE64_URL_SAFE_NO_PAD.encode(Jwk::thumb_sha256(&key)?);

        Ok(Self {
            rng,
            signing_algorithm: SigningAlgorithm::Es256,
            inner: key,
            pkcs8_der: pkcs8.as_ref().to_vec(),
            thumb,
        })
    }

    fn from_pkcs8_der(pkcs8_der: Vec<u8>) -> Result<Self, Error> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_der)?;
        let thumb = BASE64_URL_SAFE_NO_PAD.encode(Jwk::thumb_sha256(&key)?);

        Ok(Self {
            rng: SystemRandom::new(),
            signing_algorithm: SigningAlgorithm::Es256,
            inner: key,
            pkcs8_der,
            thumb,
        })
    }

    fn signed_json(
        &self,
        payload: Option<&impl Serialize>,
        protected: Header<'_>,
    ) -> Result<JoseJson, Error> {
        let protected = base64(&protected)?;
        let payload = match payload {
            Some(data) => base64(&data)?,
            None => String::new(),
        };

        let combined = format!("{protected}.{payload}");
        let signature = self.inner.sign(&self.rng, combined.as_bytes())?;
        Ok(JoseJson {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
        })
    }
}

impl Signer for Key {
    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: &'n str, url: &'u str) -> Header<'n> {
        Header {
            alg: self.signing_algorithm,
            key: KeyOrKeyId::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn key(&self) -> &Key {
        self
    }
}

trait Signer {
    fn signed_json(
        &self,
        payload: Option<&impl Serialize>,
        nonce: &str,
        url: &str,
    ) -> Result<JoseJson, Error> {
        self.key().signed_json(payload, self.header(nonce, url))
    }

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: &'n str, url: &'u str) -> Header<'n>;

    fn key(&self) -> &Key;
}

/// The response value to use for challenge responses
///
/// Refer to the methods below to see which encoding to use for your challenge type.
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-8.1>
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    fn new(challenge: &Challenge, key: &Key) -> Self {
        Self(format!("{}.{}", challenge.token, &key.thumb))
    }

    /// Get the key authorization value
    ///
    /// This can be used for HTTP-01 challenge responses.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the SHA-256 digest of the key authorization
    ///
    /// This can be used for TLS-ALPN-01 challenge responses.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8737#section-3>
    pub fn digest(&self) -> impl AsRef<[u8]> {
        digest(&SHA256, self.0.as_bytes())
    }

    /// Get the base64-encoded SHA256 digest of the key authorization
    ///
    /// This can be used for DNS-01 challenge responses.
    pub fn dns_value(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.digest())
    }
}

impl fmt::Debug for KeyAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyAuthorization").finish()
    }
}

fn nonce_from_response(rsp: &Response) -> Option<String> {
    rsp.header(REPLAY_NONCE).map(ToOwned::to_owned)
}

fn base64(data: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(data)?))
}

fn client() -> ureq::Agent {
    ureq::builder().https_only(true).build()
}

const JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE: &str = "Replay-Nonce";
