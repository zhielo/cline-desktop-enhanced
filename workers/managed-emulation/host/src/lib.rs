//! Development-only inert probe protocol. No target execution or isolation claim.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub const PROTOCOL: &str = "cline-managed-inert-probe/v1";
pub const PORT: u32 = 35555;
pub const MAX_FRAME: usize = 4096;
pub const MAX_PAYLOAD: usize = 1024;
pub const FIXTURE: &[u8] = b"cline-managed-owned-inert-fixture/v1\n";
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    protocol: String,
    session: String,
    sequence: u8,
    payload: String,
    mac: String,
}

pub fn exact_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid protocol identity");
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "Invalid protocol identity")?;
    Ok(bytes)
}

fn mac(key: &[u8; 32], session: &[u8; 16], sequence: u8, body: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("Fixed key length");
    mac.update(PROTOCOL.as_bytes());
    mac.update(&[0]);
    mac.update(session);
    mac.update(&[sequence]);
    mac.update(body);
    mac
}

pub fn encode_frame<T: Serialize>(
    key: &[u8; 32],
    session: &[u8; 16],
    sequence: u8,
    payload: &T,
) -> Result<Vec<u8>> {
    if sequence != 1 && sequence != 2 {
        return Err("Invalid direction");
    }
    let body = serde_json::to_vec(payload).map_err(|_| "Invalid payload")?;
    if body.len() > MAX_PAYLOAD {
        return Err("Payload budget");
    }
    let envelope = Envelope {
        protocol: PROTOCOL.into(),
        session: hex::encode(session),
        sequence,
        payload: hex::encode(&body),
        mac: hex::encode(mac(key, session, sequence, &body).finalize().into_bytes()),
    };
    let body = serde_json::to_vec(&envelope).map_err(|_| "Invalid envelope")?;
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err("Frame budget");
    }
    let mut output = (body.len() as u32).to_be_bytes().to_vec();
    output.extend(body);
    Ok(output)
}

pub fn receive_frame(
    input: &mut impl Read,
    key: &[u8; 32],
    session: &[u8; 16],
    sequence: u8,
) -> Result<Vec<u8>> {
    let mut header = [0; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| "Truncated header")?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("Frame budget");
    }
    let mut data = vec![0; size];
    input.read_exact(&mut data).map_err(|_| "Truncated frame")?;
    // A typed envelope rejects duplicates as well as unknown fields.
    let envelope: Envelope = serde_json::from_slice(&data).map_err(|_| "Invalid envelope")?;
    if envelope.protocol != PROTOCOL
        || envelope.session != hex::encode(session)
        || envelope.sequence != sequence
        || (sequence != 1 && sequence != 2)
        || envelope.payload.len() > MAX_PAYLOAD * 2
    {
        return Err("Probe identity mismatch");
    }
    if envelope.payload.len() % 2 != 0
        || !envelope
            .payload
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid payload");
    }
    let body = hex::decode(&envelope.payload).map_err(|_| "Invalid payload")?;
    mac(key, session, sequence, &body)
        .verify_slice(&exact_hex::<32>(&envelope.mac)?)
        .map_err(|_| "Probe authentication failed")?;
    Ok(body)
}

#[derive(Serialize)]
pub struct ProbeRequest<'a> {
    pub operation: &'static str,
    pub challenge: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProbeResponse {
    operation: String,
    challenge: String,
    fixture_sha256: String,
    execution: String,
    vm_isolation: String,
    engine_readiness: String,
}

pub fn verify_response(bytes: &[u8], challenge: &str) -> Result<ProbeResponse> {
    exact_hex::<32>(challenge)?;
    let response: ProbeResponse = serde_json::from_slice(bytes).map_err(|_| "Invalid response")?;
    if response.operation != "owned-probe-result"
        || response.challenge != challenge
        || response.fixture_sha256 != hex::encode(Sha256::digest(FIXTURE))
        || response.execution != "owned-fixture-only"
        || response.vm_isolation != "not-attested"
        || response.engine_readiness != "not-tested"
    {
        return Err("Unexpected inert-probe response");
    }
    Ok(response)
}

/// Microsoft SOCKADDR_HV bytes: family, reserved, VM GUID, Linux VSOCK service GUID.
/// This is address encoding, not proof that the VM belongs to this application.
pub fn hyperv_address(vm_id: &str) -> Result<[u8; 36]> {
    if vm_id.len() != 36 || ![8, 13, 18, 23].iter().all(|&i| vm_id.as_bytes()[i] == b'-') {
        return Err("Exact VM identity required");
    }
    let plain: String = vm_id.chars().filter(|c| *c != '-').collect();
    let uuid = exact_hex::<16>(&plain)?;
    let forbidden = [
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd",
        "e0e16197-dd56-4a10-9195-5ee7a155a838",
        "a42e7cda-d03f-480c-9cc2-a4de20abb878",
    ];
    if forbidden.contains(&vm_id) {
        return Err("Concrete child VM identity required");
    }
    let mut result = [0; 36];
    result[0..2].copy_from_slice(&34u16.to_le_bytes()); // AF_HYPERV
    let mut guid = uuid;
    guid[0..4].reverse();
    guid[4..6].reverse();
    guid[6..8].reverse();
    result[4..20].copy_from_slice(&guid);
    result[20..24].copy_from_slice(&PORT.to_le_bytes());
    // 00008ae3-facb-11e6-bd58-64006a7986d3
    result[24..36].copy_from_slice(&[
        0xcb, 0xfa, 0xe6, 0x11, 0xbd, 0x58, 0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3,
    ]);
    Ok(result)
}

pub fn write_frame(output: &mut impl Write, frame: &[u8]) -> Result<()> {
    output
        .write_all(frame)
        .map_err(|_| "Probe transport failed")
}

/// Test vector support only; callers still validate a typed response.
pub fn fixture_response(challenge: &str) -> Value {
    serde_json::json!({
        "operation": "owned-probe-result", "challenge": challenge,
        "fixtureSha256": hex::encode(Sha256::digest(FIXTURE)),
        "execution": "owned-fixture-only", "vmIsolation": "not-attested",
        "engineReadiness": "not-tested"
    })
}

/// Development lifecycle reducer; not a host operation or readiness certificate.
pub mod lifecycle;

/// Durable development journal adapter; no VM effects or readiness claims.
pub mod store;

/// Native private boot provisioning; not a VM ownership or readiness claim.
pub mod boot_media;

/// Fixed SYSTEM-only Windows root provisioning, not a running broker/service.
#[cfg(windows)]
pub mod windows_roots;

#[cfg(windows)]
pub mod windows_identity;

/// Fresh native OS boot observation, never a VM termination attestation.
#[cfg(windows)]
pub mod windows_boot;

/// Native local caller-authentication exchange, not a running service or installer.
#[cfg(windows)]
pub mod windows_ipc;

/// Explicit development-only SCM acceptance host; never bundled in the app.
#[cfg(all(windows, feature = "owned-system-acceptance"))]
pub mod windows_service;
