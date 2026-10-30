//! Authenticated fixed-role creation intent records; no VM or execution claim.
use crate::{exact_hex, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
const DOMAIN: &[u8] = b"cline-managed-creation-record/v1\0";
pub(crate) const MAX_BYTES: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    PrepareAnchor,
    Intent,
    IssueAnchor,
    Issued,
}
impl Role {
    pub(crate) const ALL: [Self; 4] = [
        Self::PrepareAnchor,
        Self::Intent,
        Self::IssueAnchor,
        Self::Issued,
    ];
    pub(crate) fn bit(self) -> u8 {
        match self {
            Self::PrepareAnchor => 1,
            Self::Intent => 2,
            Self::IssueAnchor => 4,
            Self::Issued => 8,
        }
    }
    pub(crate) fn anchor(self) -> bool {
        matches!(self, Self::PrepareAnchor | Self::IssueAnchor)
    }
    pub(crate) fn filename(self) -> &'static str {
        match self {
            Self::PrepareAnchor => "creation-prepare.anchor",
            Self::Intent => "creation-intent.json",
            Self::IssueAnchor => "creation-issue.anchor",
            Self::Issued => "creation-issued.json",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) version: u8,
    pub(crate) attempt: String,
    pub(crate) reservation: String,
    pub(crate) host_boot: String,
}
impl Context {
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err("Creation record version mismatch");
        }
        exact_hex::<16>(&self.attempt)?;
        exact_hex::<32>(&self.reservation)?;
        exact_hex::<16>(&self.host_boot)?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    context: Context,
    mac: String,
}
fn signature(key: &[u8; 32], role: Role, context: &Context) -> Result<Hmac<Sha256>> {
    context.validate()?;
    let body = serde_json::to_vec(context).map_err(|_| "Creation record encoding failed")?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "Creation authentication unavailable")?;
    mac.update(DOMAIN);
    mac.update(&[role.bit()]);
    mac.update(&(body.len() as u32).to_be_bytes());
    mac.update(&body);
    Ok(mac)
}
pub(crate) fn encode(key: &[u8; 32], role: Role, context: &Context) -> Result<Vec<u8>> {
    let mac = hex::encode(signature(key, role, context)?.finalize().into_bytes());
    let bytes = serde_json::to_vec(&Envelope {
        context: context.clone(),
        mac,
    })
    .map_err(|_| "Creation record encoding failed")?;
    if bytes.len() > MAX_BYTES {
        return Err("Creation record budget");
    }
    Ok(bytes)
}
pub(crate) fn decode(key: &[u8; 32], role: Role, bytes: &[u8]) -> Result<Context> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("Creation record budget");
    }
    let record: Envelope =
        serde_json::from_slice(bytes).map_err(|_| "Creation record schema mismatch")?;
    signature(key, role, &record.context)?
        .verify_slice(&exact_hex::<32>(&record.mac)?)
        .map_err(|_| "Creation record authentication failed")?;
    Ok(record.context)
}
/// Presence is diagnostic only. No layout restores a submission capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationStage {
    PreparationIncomplete,
    Prepared,
    IssuanceIncomplete,
    SubmissionIssued,
}
pub(crate) fn stage(mask: u8) -> Result<CreationStage> {
    match mask {
        1 => Ok(CreationStage::PreparationIncomplete),
        3 => Ok(CreationStage::Prepared),
        7 => Ok(CreationStage::IssuanceIncomplete),
        15 => Ok(CreationStage::SubmissionIssued),
        0 => Err("No creation attempt exists"),
        _ => Err("Creation record layout inconsistent; retain state"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context {
        Context {
            version: 1,
            attempt: "12".repeat(16),
            reservation: "34".repeat(32),
            host_boot: "56".repeat(16),
        }
    }
    #[test]
    fn signatures_cannot_cross_roles_keys_or_contexts() {
        let key = [7; 32];
        let base = context();
        for role in Role::ALL {
            let bytes = encode(&key, role, &base).unwrap();
            assert_eq!(decode(&key, role, &bytes).unwrap(), base);
            assert!(decode(&[8; 32], role, &bytes).is_err());
            for other in Role::ALL {
                if other != role {
                    assert!(decode(&key, other, &bytes).is_err());
                }
            }
            for field in ["attempt", "reservation", "host_boot", "version"] {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                value["context"][field] = if field == "version" {
                    2.into()
                } else {
                    "00".repeat(if field == "reservation" { 32 } else { 16 })
                        .into()
                };
                assert!(decode(&key, role, &serde_json::to_vec(&value).unwrap()).is_err());
            }
        }
    }
    #[test]
    fn duplicate_unknown_truncated_and_oversized_records_are_refused() {
        let bytes = encode(&[7; 32], Role::Intent, &context()).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for text in [
            text.replacen('{', "{\"extra\":true,", 1),
            text.replacen('{', "{\"mac\":\"00\",", 1),
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            text.replacen("\"attempt\":", "\"extra\":true,\"attempt\":", 1),
        ] {
            assert!(decode(&[7; 32], Role::Intent, text.as_bytes()).is_err());
        }
        for n in 0..bytes.len() {
            assert!(decode(&[7; 32], Role::Intent, &bytes[..n]).is_err());
        }
        assert!(decode(&[7; 32], Role::Intent, &vec![0; MAX_BYTES + 1]).is_err());
    }
    #[test]
    fn only_ordered_record_prefixes_have_a_diagnostic_stage() {
        for mask in 0..=255 {
            assert_eq!(stage(mask).is_ok(), [1, 3, 7, 15].contains(&mask));
        }
        let names: std::collections::HashSet<_> = Role::ALL.iter().map(|r| r.filename()).collect();
        assert_eq!(names.len(), 4);
        assert_eq!(Role::ALL.iter().filter(|r| r.anchor()).count(), 2);
    }
}
