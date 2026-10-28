//! Fail-closed lifecycle journal reducer, not a Hyper-V broker or an ownership attestation.
//! The caller must protect/atomically persist the journal AND its independent checkpoint
//! before performing any effect. Never reconstruct the checkpoint from untrusted journal bytes.
use crate::{exact_hex, hyperv_address, verify_response, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const DOMAIN: &[u8] = b"cline-managed-lifecycle/v1\0";
pub const MAX_JOURNAL_BYTES: usize = 65_536;
pub const MAX_EVENTS: usize = 128;

/// Claims to be checked against protected broker records, not user-provided authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Identity {
    pub installation: String,
    pub job: String,
    pub vm_id: String,
    pub image_sha256: String,
    pub host_boot: String,
}
impl Identity {
    fn validate(&self) -> Result<()> {
        exact_hex::<16>(&self.installation)?;
        exact_hex::<16>(&self.job)?;
        hyperv_address(&self.vm_id)?;
        exact_hex::<32>(&self.image_sha256)?;
        exact_hex::<16>(&self.host_boot)?;
        Ok(())
    }
}

/// No boot secret, executable, target bytes, path or shell command is journaled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "camelCase")]
pub enum Event {
    Reserve {},
    VmCreated {},
    BootRequested {
        session: String,
        challenge: String,
    },
    InertProbeRecorded {
        response: String,
    },
    StopRequested {},
    /// A fresh exact-VM observation, not helper exit, a missing PID, or host reboot.
    StopObserved {
        vm_id: String,
    },
    RemoveRequested {},
    RemovalObserved {
        vm_id: String,
    },
    RecoveryRequested {},
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Reserved,
    Created,
    BootRequested,
    InertProbed,
    StopRequired,
    Stopped,
    RemovalRequested,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub sequence: u32,
    pub mac: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    sequence: u32,
    previous: String,
    event: Event,
    mac: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    identity: Identity,
    entries: Vec<Entry>,
}

/// Immutable candidate state: append never mutates the previous journal on error.
/// A returned transition is NOT authorization to perform a host operation.
#[derive(Clone)]
pub struct Journal {
    stored: Stored,
    phase: Phase,
    active: Option<(String, String)>,
    used_sessions: Vec<String>,
    used_challenges: Vec<String>,
    recovery_required: bool,
}

fn signature(key: &[u8; 32], identity: &Identity, entry: &Entry) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("Fixed key length");
    mac.update(DOMAIN);
    // Length-delimited typed canonical data, independent of input JSON whitespace/order.
    let body = serde_json::to_vec(&(identity, entry.sequence, &entry.previous, &entry.event))
        .map_err(|_| "Invalid journal")?;
    mac.update(&(body.len() as u32).to_be_bytes());
    mac.update(&body);
    Ok(mac)
}

impl Journal {
    /// Reserve intent only. Does not create or discover a VM.
    pub fn reserve(identity: Identity, key: &[u8; 32]) -> Result<Self> {
        identity.validate()?;
        let mut journal = Self {
            stored: Stored {
                version: 1,
                identity,
                entries: Vec::new(),
            },
            phase: Phase::Reserved,
            active: None,
            used_sessions: Vec::new(),
            used_challenges: Vec::new(),
            recovery_required: false,
        };
        journal.record(Event::Reserve {}, key)?;
        Ok(journal)
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn recovery_required(&self) -> bool {
        self.recovery_required
    }
    pub fn checkpoint(&self) -> Checkpoint {
        let last = self
            .stored
            .entries
            .last()
            .expect("Nonempty reserved journal");
        Checkpoint {
            sequence: last.sequence,
            mac: last.mac.clone(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&self.stored).map_err(|_| "Invalid journal")?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err("Journal budget");
        }
        Ok(bytes)
    }

    /// Verify the FULL chain and an independently retained checkpoint. Prefix truncation
    /// cannot be detected by a MAC chain alone. Reopening always fences nonterminal work.
    pub fn restore(
        bytes: &[u8],
        expected: &Identity,
        checkpoint: &Checkpoint,
        key: &[u8; 32],
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
            return Err("Journal budget");
        }
        expected.validate()?;
        let stored: Stored = serde_json::from_slice(bytes).map_err(|_| "Invalid journal")?;
        if stored.version != 1
            || &stored.identity != expected
            || stored.entries.is_empty()
            || stored.entries.len() > MAX_EVENTS
        {
            return Err("Journal identity or budget");
        }
        let mut journal = Self {
            stored: Stored {
                version: 1,
                identity: expected.clone(),
                entries: Vec::new(),
            },
            phase: Phase::Reserved,
            active: None,
            used_sessions: Vec::new(),
            used_challenges: Vec::new(),
            recovery_required: false,
        };
        for entry in stored.entries {
            if entry.sequence != (journal.stored.entries.len() + 1) as u32
                || entry.previous != journal.previous()
            {
                return Err("Journal sequence");
            }
            signature(key, expected, &entry)?
                .verify_slice(&exact_hex::<32>(&entry.mac)?)
                .map_err(|_| "Journal authentication")?;
            journal.reduce(&entry.event)?;
            journal.stored.entries.push(entry);
        }
        if &journal.checkpoint() != checkpoint {
            return Err("Journal checkpoint mismatch");
        }
        journal.recovery_required = journal.phase != Phase::Removed;
        Ok(journal)
    }

    pub fn append(&self, event: Event, key: &[u8; 32]) -> Result<Self> {
        if self.recovery_required && event != (Event::RecoveryRequested {}) {
            return Err("Explicit recovery required; no automatic replay");
        }
        let last = self.stored.entries.last().ok_or("Missing reservation")?;
        signature(key, &self.stored.identity, last)?
            .verify_slice(&exact_hex::<32>(&last.mac)?)
            .map_err(|_| "Journal authentication")?;
        let mut candidate = self.clone();
        candidate.record(event, key)?;
        // Catch encoded-size overflow before returning a candidate to persistence.
        candidate.encode()?;
        Ok(candidate)
    }

    fn previous(&self) -> String {
        self.stored
            .entries
            .last()
            .map(|e| e.mac.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }
    fn record(&mut self, event: Event, key: &[u8; 32]) -> Result<()> {
        if self.stored.entries.len() >= MAX_EVENTS {
            return Err("Journal event budget");
        }
        let mut entry = Entry {
            sequence: (self.stored.entries.len() + 1) as u32,
            previous: self.previous(),
            event,
            mac: String::new(),
        };
        self.reduce(&entry.event)?;
        entry.mac = hex::encode(
            signature(key, &self.stored.identity, &entry)?
                .finalize()
                .into_bytes(),
        );
        self.stored.entries.push(entry);
        Ok(())
    }

    fn reduce(&mut self, event: &Event) -> Result<()> {
        use Event::*;
        use Phase as P;
        if self.stored.entries.is_empty() && event != &(Event::Reserve {}) {
            return Err("Reservation must be first");
        }
        match event {
            Reserve {} if self.stored.entries.is_empty() => self.phase = P::Reserved,
            VmCreated {} if self.phase == P::Reserved => self.phase = P::Created,
            BootRequested { session, challenge } if self.phase == P::Created => {
                exact_hex::<16>(session)?;
                exact_hex::<32>(challenge)?;
                if self.used_sessions.contains(session) || self.used_challenges.contains(challenge)
                {
                    return Err("Boot identity replay");
                }
                self.used_sessions.push(session.clone());
                self.used_challenges.push(challenge.clone());
                self.active = Some((session.clone(), challenge.clone()));
                self.phase = P::BootRequested;
            }
            InertProbeRecorded { response } if self.phase == P::BootRequested => {
                if response.len() > 1024 {
                    return Err("Probe evidence budget");
                }
                let (_, challenge) = self.active.as_ref().ok_or("Missing boot identity")?;
                verify_response(response.as_bytes(), challenge)?;
                // Inert authenticated probe evidence NEVER establishes engine readiness.
                self.phase = P::InertProbed;
            }
            StopRequested {}
                if !matches!(
                    self.phase,
                    P::Removed | P::StopRequired | P::RemovalRequested
                ) =>
            {
                self.phase = P::StopRequired;
            }
            StopObserved { vm_id }
                if self.phase == P::StopRequired && vm_id == &self.stored.identity.vm_id =>
            {
                self.active = None;
                self.phase = P::Stopped;
            }
            RemoveRequested {} if self.phase == P::Stopped => self.phase = P::RemovalRequested,
            RemovalObserved { vm_id }
                if self.phase == P::RemovalRequested && vm_id == &self.stored.identity.vm_id =>
            {
                self.phase = P::Removed;
            }
            RecoveryRequested {} if self.phase != P::Removed => {
                // Previous stop/removal receipts are historical, never current liveness proof.
                self.phase = P::StopRequired;
                self.active = None;
                self.recovery_required = false;
            }
            _ => return Err("Illegal lifecycle transition"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn even_correctly_signed_history_requires_reservation_before_effects() {
        let key = [1; 32];
        let identity = Identity {
            installation: "11".repeat(16),
            job: "22".repeat(16),
            vm_id: "11223344-5566-7788-99aa-bbccddeeff00".into(),
            image_sha256: "33".repeat(32),
            host_boot: "44".repeat(16),
        };
        for event in [
            Event::VmCreated {},
            Event::RecoveryRequested {},
            Event::StopRequested {},
        ] {
            let mut entry = Entry {
                sequence: 1,
                previous: "0".repeat(64),
                event,
                mac: String::new(),
            };
            entry.mac = hex::encode(
                signature(&key, &identity, &entry)
                    .unwrap()
                    .finalize()
                    .into_bytes(),
            );
            let checkpoint = Checkpoint {
                sequence: 1,
                mac: entry.mac.clone(),
            };
            let stored = Stored {
                version: 1,
                identity: identity.clone(),
                entries: vec![entry],
            };
            assert!(Journal::restore(
                &serde_json::to_vec(&stored).unwrap(),
                &identity,
                &checkpoint,
                &key
            )
            .is_err());
        }
    }
}
