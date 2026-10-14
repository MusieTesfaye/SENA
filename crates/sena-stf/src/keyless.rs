//! OIDC keyless accounts: claim validation and ephemeral key binding.
//!
//! The promise is that a user signs in with Google or Apple and controls a
//! self-custodial account, with no seed phrase anywhere. The mechanism is:
//!
//! 1. the client generates a short-lived **ephemeral key pair** (EPK);
//! 2. it signs in, asking the provider to embed a commitment to that EPK in the
//!    JWT's `nonce` claim;
//! 3. it proves, in zero knowledge, that it holds such a JWT;
//! 4. the chain accepts transactions signed by the EPK, for an account derived
//!    from the JWT's `aud` and `sub` plus a private pepper.
//!
//! # Where these systems actually break
//!
//! Not usually in the proof system. The failure that recurs is **weak binding**:
//! if the chain does not check that the JWT's `nonce` commits to *this*
//! ephemeral key, then anyone who obtains a valid JWT — from a log, a referrer
//! header, a malicious relying party — can pair it with a key they generated
//! and take the account.
//!
//! So that check is the substance of this module, and it is implemented and
//! tested here rather than deferred to the proof system:
//!
//! - the `nonce` must equal the commitment to the presented EPK and expiry;
//! - the EPK must not have expired, and its lifetime must be bounded;
//! - the issuer must be one the network approves;
//! - the `aud` scoping that makes accounts unlinkable across applications must
//!   be preserved.
//!
//! # What is not implemented
//!
//! Verifying that the JWT is genuinely signed by the provider. That is what the
//! zero-knowledge proof attests to, and this crate does not verify proofs —
//! [`KeylessVerifier`] is the seam where an implementation plugs in, and no
//! implementation ships enabled. Everything here therefore establishes that a
//! *presented* JWT is correctly bound and current; it does not establish that
//! the JWT is real. Both are required, and the second is tracked as the primary
//! outstanding item for keyless accounts.

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sena_primitives::{CanonicalEncoder, Hash256, L2Address};
use serde::{Deserialize, Serialize};

/// Domain tag for the ephemeral key commitment.
const EPK_COMMITMENT: &[u8] = b"SENA:v1:epk-nonce";

/// The claims SENA reads from an OIDC identity token.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer — the identity provider.
    pub iss: String,
    /// Audience — the application the user signed in to.
    ///
    /// Part of the address derivation, which is what makes the same person
    /// unlinkable across two applications.
    pub aud: String,
    /// Subject — the provider's stable identifier for the user.
    pub sub: String,
    /// Expiry of the token itself, as a Unix timestamp.
    pub exp: u64,
    /// Issued-at time, as a Unix timestamp.
    #[serde(default)]
    pub iat: u64,
    /// The commitment to the ephemeral key, as a hex string.
    ///
    /// This is the binding. Everything else in a keyless system rests on it.
    pub nonce: String,
}

/// Why a keyless authorisation was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum KeylessError {
    /// The token is not three base64url segments separated by dots.
    #[error("token is not a well-formed JWT")]
    Malformed,
    /// A segment was not valid base64url.
    #[error("token segment is not valid base64url")]
    BadEncoding,
    /// The claims payload was not the expected JSON object.
    #[error("token claims could not be read")]
    BadClaims,
    /// The issuer is not one this network accepts.
    #[error("issuer '{issuer}' is not an approved identity provider")]
    UntrustedIssuer {
        /// The issuer presented.
        issuer: String,
    },
    /// The identity token has expired.
    #[error("identity token expired at {expired_at}, now {now}")]
    TokenExpired {
        /// When it expired.
        expired_at: u64,
        /// The current time.
        now: u64,
    },
    /// The ephemeral key has expired.
    #[error("ephemeral key expired at {expired_at}, now {now}")]
    EphemeralKeyExpired {
        /// When it expired.
        expired_at: u64,
        /// The current time.
        now: u64,
    },
    /// The ephemeral key was issued with too long a lifetime.
    #[error("ephemeral key lifetime of {requested}s exceeds the maximum of {maximum}s")]
    EphemeralKeyTooLongLived {
        /// The lifetime asked for.
        requested: u64,
        /// The maximum permitted.
        maximum: u64,
    },
    /// The token's nonce does not commit to the presented ephemeral key.
    ///
    /// The attack this refuses: pairing a genuine JWT obtained from somewhere
    /// else with a freshly generated key, and taking the account.
    #[error("token nonce does not commit to the presented ephemeral key")]
    NonceMismatch,
    /// The claims do not derive the address the transaction claims to be from.
    #[error("claims derive a different address than the transaction's sender")]
    AddressMismatch,
    /// No proof verifier is configured, so the token cannot be shown to be real.
    #[error(
        "keyless proof verification is not available: the identity token is correctly bound and \
         current, but nothing here can establish that the provider actually issued it"
    )]
    ProofVerificationUnavailable,
}

/// The network's policy for accepting keyless identities.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeylessPolicy {
    /// Issuers this network accepts, by their `iss` claim.
    pub approved_issuers: BTreeSet<String>,
    /// The longest an ephemeral key may be valid for, in seconds.
    ///
    /// The EPK is held by a client application and is the thing that can
    /// actually move funds, so its lifetime is the window in which a
    /// compromised device can act. Keeping it to hours rather than days is what
    /// makes "no seed phrase" safe rather than merely convenient.
    pub max_ephemeral_key_lifetime: u64,
}

impl KeylessPolicy {
    /// A policy accepting Google and Apple, with a two-hour key lifetime.
    #[must_use]
    pub fn default_providers() -> Self {
        Self {
            approved_issuers: ["https://accounts.google.com", "https://appleid.apple.com"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            max_ephemeral_key_lifetime: 2 * 60 * 60,
        }
    }
}

/// Computes the nonce a JWT must carry to bind an ephemeral key.
///
/// The commitment covers the key *and* its expiry, so a token cannot be replayed
/// with a later expiry to extend the key's life. The blinder is a client secret
/// that stops an observer correlating a public nonce back to a known key.
///
/// ```
/// use sena_stf::keyless::epk_commitment;
///
/// let a = epk_commitment(&[1; 32], 1_000, b"blinder");
/// let b = epk_commitment(&[1; 32], 2_000, b"blinder");
/// assert_ne!(a, b, "the expiry is committed to as well as the key");
/// ```
#[must_use]
pub fn epk_commitment(ephemeral_public_key: &[u8; 32], expiry: u64, blinder: &[u8]) -> String {
    Hash256::commit(
        CanonicalEncoder::new(EPK_COMMITMENT)
            .field(ephemeral_public_key)
            .u64(expiry)
            .field(blinder),
    )
    .to_hex()
}

/// Reads a JWT's claims **without verifying its signature**.
///
/// The name says what it does. Nothing this returns has been shown to come from
/// the issuer it names; that is what proof verification is for.
///
/// # Errors
///
/// Returns [`KeylessError`] if the token is not a well-formed JWT or its claims
/// cannot be read.
pub fn parse_claims_unverified(token: &str) -> Result<JwtClaims, KeylessError> {
    let mut segments = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(KeylessError::Malformed);
    };

    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| KeylessError::BadEncoding)?;
    serde_json::from_slice(&decoded).map_err(|_| KeylessError::BadClaims)
}

/// A keyless authorisation as presented by a client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeylessAuth<'a> {
    /// The identity token.
    pub token: &'a str,
    /// The ephemeral public key that signed the transaction.
    pub ephemeral_public_key: &'a [u8; 32],
    /// When the ephemeral key expires.
    pub ephemeral_expiry: u64,
    /// The blinder used in the nonce commitment.
    pub blinder: &'a [u8],
    /// The pepper the account's address derives from.
    pub pepper: &'a [u8],
    /// The zero-knowledge proof, passed to the configured verifier.
    pub proof: &'a [u8],
}

/// Checks everything about a keyless authorisation except that the token is real.
///
/// Returns the address the claims derive, so a caller can compare it against the
/// transaction's sender.
///
/// # Errors
///
/// Returns [`KeylessError`] if the token is malformed, expired, issued by an
/// unapproved provider, or — the important one — if its nonce does not commit to
/// the presented ephemeral key.
pub fn check_binding(
    auth: &KeylessAuth<'_>,
    policy: &KeylessPolicy,
    now: u64,
) -> Result<L2Address, KeylessError> {
    let claims = parse_claims_unverified(auth.token)?;

    if !policy.approved_issuers.contains(&claims.iss) {
        return Err(KeylessError::UntrustedIssuer { issuer: claims.iss });
    }

    if claims.exp <= now {
        return Err(KeylessError::TokenExpired {
            expired_at: claims.exp,
            now,
        });
    }

    if auth.ephemeral_expiry <= now {
        return Err(KeylessError::EphemeralKeyExpired {
            expired_at: auth.ephemeral_expiry,
            now,
        });
    }

    let lifetime = auth.ephemeral_expiry.saturating_sub(now);
    if lifetime > policy.max_ephemeral_key_lifetime {
        return Err(KeylessError::EphemeralKeyTooLongLived {
            requested: lifetime,
            maximum: policy.max_ephemeral_key_lifetime,
        });
    }

    // The binding check. Constant-time comparison is unnecessary here: both
    // values are public, and an attacker learns nothing from timing that they
    // could not compute themselves.
    let expected = epk_commitment(
        auth.ephemeral_public_key,
        auth.ephemeral_expiry,
        auth.blinder,
    );
    if claims.nonce != expected {
        return Err(KeylessError::NonceMismatch);
    }

    Ok(L2Address::derive_from_oidc(
        &claims.aud,
        &claims.sub,
        auth.pepper,
    ))
}

/// Verifies that a presented identity token is genuine.
///
/// The seam where a proof system plugs in. No implementation ships enabled:
/// accepting a keyless transaction without one would let anyone spend from any
/// keyless account by presenting claims they made up.
pub trait KeylessVerifier {
    /// Returns `Ok(())` if the proof attests to the claims.
    ///
    /// # Errors
    ///
    /// Returns [`KeylessError`] if the proof does not verify.
    fn verify(&self, auth: &KeylessAuth<'_>, claims: &JwtClaims) -> Result<(), KeylessError>;
}

/// The verifier used when none is configured: refuses everything.
///
/// Refusing is the only safe default. A verifier that accepted anything would
/// make every keyless account spendable by anyone, and a partial check that
/// looked like verification would be worse than none.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVerifier;

impl KeylessVerifier for NoVerifier {
    fn verify(&self, _auth: &KeylessAuth<'_>, _claims: &JwtClaims) -> Result<(), KeylessError> {
        Err(KeylessError::ProofVerificationUnavailable)
    }
}

/// Runs the full keyless check: binding, then proof.
///
/// # Errors
///
/// Returns [`KeylessError`] if the binding checks fail, if the derived address
/// is not `expected_sender`, or if the proof does not verify.
pub fn authorise(
    auth: &KeylessAuth<'_>,
    expected_sender: &L2Address,
    policy: &KeylessPolicy,
    verifier: &impl KeylessVerifier,
    now: u64,
) -> Result<(), KeylessError> {
    let derived = check_binding(auth, policy, now)?;
    if derived != *expected_sender {
        return Err(KeylessError::AddressMismatch);
    }
    let claims = parse_claims_unverified(auth.token)?;
    verifier.verify(auth, &claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPK: [u8; 32] = [7; 32];
    const BLINDER: &[u8] = b"client-blinder";
    const PEPPER: &[u8] = b"user-pepper-value";
    const NOW: u64 = 1_000_000;

    fn policy() -> KeylessPolicy {
        KeylessPolicy::default_providers()
    }

    fn token_with(claims: &JwtClaims) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        // The signature is not checked here; that is the proof's job.
        format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(b"signature")
        )
    }

    fn valid_claims() -> JwtClaims {
        JwtClaims {
            iss: "https://accounts.google.com".to_owned(),
            aud: "sena-wallet.example".to_owned(),
            sub: "108241999".to_owned(),
            exp: NOW + 3_600,
            iat: NOW,
            nonce: epk_commitment(&EPK, NOW + 3_600, BLINDER),
        }
    }

    fn auth(token: &str, expiry: u64) -> KeylessAuth<'_> {
        KeylessAuth {
            token,
            ephemeral_public_key: &EPK,
            ephemeral_expiry: expiry,
            blinder: BLINDER,
            pepper: PEPPER,
            proof: &[],
        }
    }

    #[test]
    fn a_correctly_bound_token_derives_its_address() {
        let claims = valid_claims();
        let token = token_with(&claims);
        let derived = check_binding(&auth(&token, NOW + 3_600), &policy(), NOW).unwrap();
        assert_eq!(
            derived,
            L2Address::derive_from_oidc(&claims.aud, &claims.sub, PEPPER)
        );
    }

    #[test]
    fn a_token_bound_to_another_key_is_refused() {
        // The central attack: a genuine JWT, obtained from a log or a malicious
        // relying party, paired with a key the attacker generated.
        let claims = valid_claims();
        let token = token_with(&claims);

        let attacker_key = [0xAA; 32];
        let stolen = KeylessAuth {
            token: &token,
            ephemeral_public_key: &attacker_key,
            ephemeral_expiry: NOW + 3_600,
            blinder: BLINDER,
            pepper: PEPPER,
            proof: &[],
        };
        assert_eq!(
            check_binding(&stolen, &policy(), NOW).unwrap_err(),
            KeylessError::NonceMismatch
        );
    }

    #[test]
    fn the_expiry_is_committed_to_as_well_as_the_key() {
        // Otherwise a token could be replayed with a later expiry, extending
        // the ephemeral key's life indefinitely.
        let claims = valid_claims();
        let token = token_with(&claims);
        let extended = auth(&token, NOW + 7_200);
        assert_eq!(
            check_binding(&extended, &policy(), NOW).unwrap_err(),
            KeylessError::NonceMismatch
        );
    }

    #[test]
    fn a_different_blinder_does_not_bind() {
        let claims = valid_claims();
        let token = token_with(&claims);
        let wrong = KeylessAuth {
            blinder: b"other",
            ..auth(&token, NOW + 3_600)
        };
        assert_eq!(
            check_binding(&wrong, &policy(), NOW).unwrap_err(),
            KeylessError::NonceMismatch
        );
    }

    #[test]
    fn an_expired_token_is_refused() {
        let mut claims = valid_claims();
        claims.exp = NOW - 1;
        claims.nonce = epk_commitment(&EPK, NOW + 3_600, BLINDER);
        let token = token_with(&claims);
        assert!(matches!(
            check_binding(&auth(&token, NOW + 3_600), &policy(), NOW).unwrap_err(),
            KeylessError::TokenExpired { .. }
        ));
    }

    #[test]
    fn an_expired_ephemeral_key_is_refused() {
        let mut claims = valid_claims();
        claims.nonce = epk_commitment(&EPK, NOW - 1, BLINDER);
        let token = token_with(&claims);
        assert!(matches!(
            check_binding(&auth(&token, NOW - 1), &policy(), NOW).unwrap_err(),
            KeylessError::EphemeralKeyExpired { .. }
        ));
    }

    #[test]
    fn an_over_long_ephemeral_key_is_refused() {
        // The EPK is what can actually move funds, so its lifetime bounds the
        // window a compromised device has.
        let far = NOW + 30 * 24 * 60 * 60;
        let mut claims = valid_claims();
        claims.exp = far + 1;
        claims.nonce = epk_commitment(&EPK, far, BLINDER);
        let token = token_with(&claims);
        assert!(matches!(
            check_binding(&auth(&token, far), &policy(), NOW).unwrap_err(),
            KeylessError::EphemeralKeyTooLongLived { .. }
        ));
    }

    #[test]
    fn an_unapproved_issuer_is_refused() {
        let mut claims = valid_claims();
        claims.iss = "https://evil.example".to_owned();
        let token = token_with(&claims);
        assert!(matches!(
            check_binding(&auth(&token, NOW + 3_600), &policy(), NOW).unwrap_err(),
            KeylessError::UntrustedIssuer { .. }
        ));
    }

    #[test]
    fn applications_get_unlinkable_addresses_for_one_user() {
        let mut first = valid_claims();
        first.aud = "app-one".to_owned();
        let mut second = valid_claims();
        second.aud = "app-two".to_owned();

        let a = check_binding(&auth(&token_with(&first), NOW + 3_600), &policy(), NOW).unwrap();
        let b = check_binding(&auth(&token_with(&second), NOW + 3_600), &policy(), NOW).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_malformed_token_is_refused() {
        for bad in ["", "one.two", "a.b.c.d", "not-a-jwt"] {
            assert!(check_binding(&auth(bad, NOW + 3_600), &policy(), NOW).is_err());
        }
    }

    #[test]
    fn a_token_with_unreadable_claims_is_refused() {
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(b"not json"),
            URL_SAFE_NO_PAD.encode(b"sig")
        );
        assert_eq!(
            check_binding(&auth(&token, NOW + 3_600), &policy(), NOW).unwrap_err(),
            KeylessError::BadClaims
        );
    }

    #[test]
    fn authorisation_still_fails_without_a_proof_verifier() {
        // Binding and freshness are established; authenticity is not. Refusing
        // is the only safe outcome.
        let claims = valid_claims();
        let token = token_with(&claims);
        let sender = L2Address::derive_from_oidc(&claims.aud, &claims.sub, PEPPER);

        assert_eq!(
            authorise(
                &auth(&token, NOW + 3_600),
                &sender,
                &policy(),
                &NoVerifier,
                NOW
            )
            .unwrap_err(),
            KeylessError::ProofVerificationUnavailable
        );
    }

    #[test]
    fn authorisation_refuses_a_sender_the_claims_do_not_derive() {
        let claims = valid_claims();
        let token = token_with(&claims);
        let someone_else = L2Address::from_bytes([9; 32]);
        assert_eq!(
            authorise(
                &auth(&token, NOW + 3_600),
                &someone_else,
                &policy(),
                &NoVerifier,
                NOW
            )
            .unwrap_err(),
            KeylessError::AddressMismatch
        );
    }

    #[test]
    fn determinism_the_commitment_is_stable() {
        let a = epk_commitment(&EPK, 1_234, BLINDER);
        println!("root={a}");
        assert_eq!(a, epk_commitment(&EPK, 1_234, BLINDER));
    }
}
