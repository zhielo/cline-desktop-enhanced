//! Authenticated provider-response data, not native provenance or VM ownership.
use crate::{
    creation_records::{Context, Role, MAX_BYTES},
    hyperv_creation::DefinitionReply,
    Result,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
const DOMAIN: &[u8] = b"cline-managed-creation-reply/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum Reply {
    Completed {
        system: String,
    },
    Pending {
        job: String,
        candidate: Option<String>,
    },
}
impl Reply {
    fn from_reply(reply: &DefinitionReply) -> Self {
        match reply {
            DefinitionReply::Completed(system) => Self::Completed {
                system: system.relative_path(),
            },
            DefinitionReply::Pending { job, candidate } => Self::Pending {
                job: job.relative_path(),
                candidate: candidate.as_ref().map(|s| s.relative_path()),
            },
        }
    }
    fn validated(&self) -> Result<DefinitionReply> {
        // Only canonical relative paths are persisted. This fixed validation
        // label is not a native hostname observation or provider invocation.
        let reply = match self {
            Self::Completed { system } => {
                DefinitionReply::decode(0, Some(system), None, "RECORD-VALIDATION")?
            }
            Self::Pending { job, candidate } => {
                DefinitionReply::decode(4096, candidate.as_deref(), Some(job), "RECORD-VALIDATION")?
            }
        };
        if &Self::from_reply(&reply) != self {
            return Err("Creation reply paths are not canonical");
        }
        Ok(reply)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Data {
    pub(crate) context: Context,
    reply: Reply,
}
impl Data {
    pub(crate) fn new(context: &Context, reply: &DefinitionReply) -> Result<Self> {
        context.validate()?;
        let reply = Reply::from_reply(reply);
        reply.validated()?;
        Ok(Self {
            context: context.clone(),
            reply,
        })
    }
    pub(crate) fn reply(&self) -> Result<DefinitionReply> {
        self.reply.validated()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    data: Data,
    mac: String,
}
fn signature(key: &[u8; 32], role: Role, data: &Data) -> Result<Hmac<Sha256>> {
    if !Role::REPLY.contains(&role) {
        return Err("Creation reply record role mismatch");
    }
    data.context.validate()?;
    data.reply()?;
    let body = serde_json::to_vec(data).map_err(|_| "Creation reply encoding failed")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "Creation reply authentication unavailable")?;
    mac.update(DOMAIN);
    mac.update(&[role.bit()]);
    mac.update(&(body.len() as u32).to_be_bytes());
    mac.update(&body);
    Ok(mac)
}
pub(crate) fn encode(key: &[u8; 32], role: Role, data: &Data) -> Result<Vec<u8>> {
    let mac = hex::encode(signature(key, role, data)?.finalize().into_bytes());
    let bytes = serde_json::to_vec(&Envelope {
        data: data.clone(),
        mac,
    })
    .map_err(|_| "Creation reply encoding failed")?;
    if bytes.len() > MAX_BYTES {
        return Err("Creation reply record budget");
    }
    Ok(bytes)
}
pub(crate) fn decode(key: &[u8; 32], role: Role, bytes: &[u8]) -> Result<Data> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("Creation reply record budget");
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| "Creation reply schema mismatch")?;
    signature(key, role, &envelope.data)?
        .verify_slice(&crate::exact_hex::<32>(&envelope.mac)?)
        .map_err(|_| "Creation reply authentication failed")?;
    Ok(envelope.data)
}
#[cfg(test)]
mod tests {
    use super::*;
    const VM: &str = "Msvm_ComputerSystem.Name=\"12345678-1234-4234-8234-123456789abc\"";
    const JOB: &str = "Msvm_ConcreteJob.InstanceID=\"job:owned-1\"";
    fn context() -> Context {
        Context {
            version: 1,
            attempt: "12".repeat(16),
            reservation: "34".repeat(32),
            host_boot: "56".repeat(16),
        }
    }
    fn data() -> Data {
        Data::new(
            &context(),
            &DefinitionReply::decode(4096, Some(VM), Some(JOB), "OWNED").unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn pending_and_completed_remain_distinct_without_ownership_promotion() {
        for (code, system, job) in [
            (0, Some(VM), None),
            (4096, Some(VM), Some(JOB)),
            (4096, None, Some(JOB)),
        ] {
            let reply = DefinitionReply::decode(code, system, job, "OWNED").unwrap();
            let data = Data::new(&context(), &reply).unwrap();
            for role in Role::REPLY {
                let bytes = encode(&[7; 32], role, &data).unwrap();
                assert_eq!(
                    decode(&[7; 32], role, &bytes).unwrap().reply().unwrap(),
                    reply
                );
            }
        }
    }
    #[test]
    fn reply_mac_cannot_cross_roles_keys_contexts_or_payloads() {
        let bytes = encode(&[7; 32], Role::Reply, &data()).unwrap();
        assert!(decode(&[7; 32], Role::ReplyAnchor, &bytes).is_err());
        assert!(decode(&[8; 32], Role::Reply, &bytes).is_err());
        for role in Role::ALL {
            assert!(encode(&[7; 32], role, &data()).is_err());
            assert!(decode(&[7; 32], role, &bytes).is_err());
        }
        let text = String::from_utf8(bytes).unwrap();
        for changed in [
            text.replace(&"12".repeat(16), &"13".repeat(16)),
            text.replace(&"34".repeat(32), &"35".repeat(32)),
            text.replace(&"56".repeat(16), &"57".repeat(16)),
            text.replace("job:owned-1", "job:owned-2"),
            text.replace("123456789abc", "123456789abd"),
        ] {
            assert!(decode(&[7; 32], Role::Reply, changed.as_bytes()).is_err());
        }
    }
    #[test]
    fn malformed_duplicate_unknown_and_noncanonical_data_is_rejected() {
        let bytes = encode(&[7; 32], Role::Reply, &data()).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for bad in [
            Vec::new(),
            bytes[..bytes.len() - 1].to_vec(),
            vec![b' '; MAX_BYTES + 1],
            text.replacen('{', "{\"unknown\":true,", 1).into_bytes(),
            text.replace(
                "\"state\":\"Pending\"",
                "\"state\":\"Pending\",\"state\":\"Completed\"",
            )
            .into_bytes(),
        ] {
            assert!(decode(&[7; 32], Role::Reply, &bad).is_err());
        }
        for system in [
            VM.to_ascii_uppercase(),
            format!(r"\\OWNED\root\virtualization\v2:{VM}"),
            "Msvm_ComputerSystem.Name=\"*\"".into(),
        ] {
            let mut invalid = data();
            invalid.reply = Reply::Completed { system };
            assert!(encode(&[7; 32], Role::Reply, &invalid).is_err());
        }
        assert!(crate::creation_records::decode(&[7; 32], Role::Intent, &bytes).is_err());
    }
}
