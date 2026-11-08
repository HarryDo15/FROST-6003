use base64::{engine::general_purpose::STANDARD, Engine};
use frost_ed25519 as frost;
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Read};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Keygen {
        threshold: u16,
        total: u16,
    },
    Commit {
        key_package: String,
    },
    Sign {
        key_package: String,
        nonces: String,
        message: String,
        commitments: BTreeMap<String, String>,
    },
    Aggregate {
        message: String,
        commitments: BTreeMap<String, String>,
        shares: BTreeMap<String, String>,
        public_key_package: String,
    },
    Verify {
        message: String,
        signature: String,
        public_key_package: String,
    },
    ValidateCommitment {
        commitment: String,
    },
    ValidateKeyPackage {
        key_package: String,
        node_id: String,
        public_key_package: String,
    },
    ValidateVault {
        public_key_package: String,
        threshold: u16,
        total: u16,
        verifying_key: String,
    },
}

fn identifier(value: &str) -> Result<frost::Identifier> {
    let number: u16 = value.parse()?;
    if number.to_string() != value {
        return Err("noncanonical node identifier".into());
    }
    Ok(number.try_into()?)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(value)?)
}

fn key_package(value: &str) -> Result<frost::keys::KeyPackage> {
    let key = frost::keys::KeyPackage::deserialize(&decode(value)?)?;
    if *key.min_signers() < 2
        || frost::keys::VerifyingShare::from(*key.signing_share()) != *key.verifying_share()
    {
        return Err("invalid key package".into());
    }
    Ok(key)
}

fn commitments(
    values: BTreeMap<String, String>,
) -> Result<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> {
    values
        .into_iter()
        .map(|(node, value)| {
            Ok((
                identifier(&node)?,
                frost::round1::SigningCommitments::deserialize(&decode(&value)?)?,
            ))
        })
        .collect()
}

fn execute(operation: Operation) -> Result<Value> {
    match operation {
        Operation::Keygen { threshold, total } => {
            if threshold < 2 || threshold > total || total > 255 {
                return Err("need 2 <= threshold <= total <= 255".into());
            }
            let (shares, public) = frost::keys::generate_with_dealer(
                total,
                threshold,
                frost::keys::IdentifierList::Default,
                &mut OsRng,
            )?;
            let mut keys = BTreeMap::new();
            for node in 1..=total {
                let share = shares
                    .get(&node.try_into()?)
                    .ok_or("missing dealer share")?;
                let key = frost::keys::KeyPackage::try_from(share.clone())?;
                keys.insert(node.to_string(), STANDARD.encode(key.serialize()?));
            }
            Ok(json!({
                "key_packages": keys,
                "public_key_package": STANDARD.encode(public.serialize()?),
                "verifying_key": STANDARD.encode(public.verifying_key().serialize()?),
            }))
        }
        Operation::Commit { key_package: value } => {
            let key = key_package(&value)?;
            let (nonces, commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
            Ok(json!({
                "nonces": STANDARD.encode(nonces.serialize()?),
                "commitment": STANDARD.encode(commitment.serialize()?),
            }))
        }
        Operation::Sign {
            key_package: value,
            nonces,
            message,
            commitments: values,
        } => {
            let key = key_package(&value)?;
            let nonces = frost::round1::SigningNonces::deserialize(&decode(&nonces)?)?;
            let commitments = commitments(values)?;
            let own_commitment = frost::round1::SigningCommitments::from(&nonces);
            if commitments.get(key.identifier()) != Some(&own_commitment) {
                return Err("signer commitment does not match its nonces".into());
            }
            let package = frost::SigningPackage::new(commitments, &decode(&message)?);
            let share = frost::round2::sign(&package, &nonces, &key)?;
            Ok(json!({"share": STANDARD.encode(share.serialize())}))
        }
        Operation::Aggregate {
            message,
            commitments: values,
            shares,
            public_key_package,
        } => {
            let public = frost::keys::PublicKeyPackage::deserialize(&decode(&public_key_package)?)?;
            let commitments = commitments(values)?;
            let threshold = public.min_signers().ok_or("missing threshold")?;
            if commitments.len() < usize::from(threshold)
                || commitments
                    .keys()
                    .any(|node| !public.verifying_shares().contains_key(node))
            {
                return Err("invalid signing participants".into());
            }
            let shares: BTreeMap<_, _> = shares
                .into_iter()
                .map(|(node, value)| {
                    Ok((
                        identifier(&node)?,
                        frost::round2::SignatureShare::deserialize(&decode(&value)?)?,
                    ))
                })
                .collect::<Result<_>>()?;
            if !commitments.keys().eq(shares.keys()) {
                return Err("signature shares do not match commitments".into());
            }
            let package = frost::SigningPackage::new(commitments, &decode(&message)?);
            let signature = frost::aggregate(&package, &shares, &public)?;
            Ok(json!({"signature": STANDARD.encode(signature.serialize()?)}))
        }
        Operation::Verify {
            message,
            signature,
            public_key_package,
        } => {
            let public = frost::keys::PublicKeyPackage::deserialize(&decode(&public_key_package)?)?;
            let signature = frost::Signature::deserialize(&decode(&signature)?)?;
            let valid = public
                .verifying_key()
                .verify(&decode(&message)?, &signature)
                .is_ok();
            Ok(json!({"valid": valid}))
        }
        Operation::ValidateCommitment { commitment } => {
            frost::round1::SigningCommitments::deserialize(&decode(&commitment)?)?;
            Ok(json!({"valid": true}))
        }
        Operation::ValidateKeyPackage {
            key_package: value,
            node_id,
            public_key_package,
        } => {
            let key = key_package(&value)?;
            let public = frost::keys::PublicKeyPackage::deserialize(&decode(&public_key_package)?)?;
            let node = identifier(&node_id)?;
            if *key.identifier() != node
                || public.verifying_shares().get(&node) != Some(key.verifying_share())
                || public.verifying_key() != key.verifying_key()
                || public.min_signers() != Some(*key.min_signers())
            {
                return Err("key package does not match node and vault".into());
            }
            Ok(json!({"valid": true}))
        }
        Operation::ValidateVault {
            public_key_package,
            threshold,
            total,
            verifying_key,
        } => {
            let public = frost::keys::PublicKeyPackage::deserialize(&decode(&public_key_package)?)?;
            let verifying_key = frost::VerifyingKey::deserialize(&decode(&verifying_key)?)?;
            if threshold < 2
                || threshold > total
                || total > 255
                || public.min_signers() != Some(threshold)
                || public.verifying_shares().len() != usize::from(total)
                || public.verifying_key() != &verifying_key
            {
                return Err("public key package does not match vault".into());
            }
            for node in 1..=total {
                if !public.verifying_shares().contains_key(&node.try_into()?) {
                    return Err("public key package has unexpected participants".into());
                }
            }
            Ok(json!({"valid": true}))
        }
    }
}

fn run() -> Result<Value> {
    let mut input = String::new();
    io::stdin().take(4_194_305).read_to_string(&mut input)?;
    if input.len() > 4_194_304 {
        return Err("request exceeds size limit".into());
    }
    execute(serde_json::from_str(&input)?)
}

fn main() {
    match run() {
        Ok(response) => println!("{response}"),
        Err(_) => {
            println!(
                "{}",
                json!({"error": "invalid FROST operation or cryptographic input"})
            );
            std::process::exit(1);
        }
    }
}
