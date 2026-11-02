use cline_managed_inert_probe::{
    fixture_response,
    lifecycle::{Checkpoint, Event, Identity, Journal, Phase, MAX_EVENTS, MAX_JOURNAL_BYTES},
};
use serde_json::{json, Value};

const KEY: [u8; 32] = [0x31; 32];
fn identity() -> Identity {
    Identity {
        installation: "11".repeat(16),
        job: "22".repeat(16),
        vm_id: "11223344-5566-7788-99aa-bbccddeeff00".into(),
        image_sha256: "33".repeat(32),
        host_boot: "44".repeat(16),
    }
}
fn reserved() -> Journal {
    Journal::reserve(identity(), &KEY).unwrap()
}
fn boot() -> Event {
    Event::BootRequested {
        session: "55".repeat(16),
        challenge: "66".repeat(32),
    }
}
fn running() -> Journal {
    reserved()
        .append(Event::VmCreated {}, &KEY)
        .unwrap()
        .append(boot(), &KEY)
        .unwrap()
}
fn observed() -> Event {
    Event::StopObserved {
        vm_id: identity().vm_id,
    }
}
fn restore(j: &Journal) -> Journal {
    Journal::restore(&j.encode().unwrap(), &identity(), &j.checkpoint(), &KEY).unwrap()
}

#[test]
fn complete_inert_lifecycle_never_claims_engine_or_isolation_readiness() {
    let probe = Event::InertProbeRecorded {
        response: fixture_response(&"66".repeat(32)).to_string(),
    };
    let journal = running().append(probe, &KEY).unwrap();
    assert_eq!(journal.phase(), Phase::InertProbed);
    let data = String::from_utf8(journal.encode().unwrap()).unwrap();
    assert!(data.contains("not-attested") && data.contains("not-tested"));
    let journal = journal
        .append(Event::StopRequested {}, &KEY)
        .unwrap()
        .append(observed(), &KEY)
        .unwrap()
        .append(Event::RemoveRequested {}, &KEY)
        .unwrap()
        .append(
            Event::RemovalObserved {
                vm_id: identity().vm_id,
            },
            &KEY,
        )
        .unwrap();
    let restored = restore(&journal);
    assert_eq!(restored.phase(), Phase::Removed);
    assert!(!restored.recovery_required());
    assert!(restored.append(Event::RecoveryRequested {}, &KEY).is_err());
    assert!(restored.append(Event::VmCreated {}, &KEY).is_err());
}

#[test]
fn stop_intent_and_exact_fresh_observation_are_required_before_removal() {
    for journal in [
        reserved(),
        reserved().append(Event::VmCreated {}, &KEY).unwrap(),
        running(),
    ] {
        for event in [
            observed(),
            Event::RemoveRequested {},
            Event::RemovalObserved {
                vm_id: identity().vm_id,
            },
        ] {
            assert!(journal.append(event, &KEY).is_err());
        }
        let stopping = journal.append(Event::StopRequested {}, &KEY).unwrap();
        assert!(stopping.append(Event::RemoveRequested {}, &KEY).is_err());
        assert!(stopping
            .append(
                Event::StopObserved {
                    vm_id: "foreign-vm".into()
                },
                &KEY
            )
            .is_err());
        assert_eq!(
            stopping.append(observed(), &KEY).unwrap().phase(),
            Phase::Stopped
        );
    }
}

#[test]
fn reopened_work_is_fenced_even_when_previous_stop_was_recorded() {
    let stopped = running()
        .append(Event::StopRequested {}, &KEY)
        .unwrap()
        .append(observed(), &KEY)
        .unwrap();
    let removing = stopped.append(Event::RemoveRequested {}, &KEY).unwrap();
    for journal in [reserved(), running(), stopped, removing] {
        let reopened = restore(&journal);
        assert!(reopened.recovery_required());
        for event in [
            Event::VmCreated {},
            boot(),
            observed(),
            Event::RemoveRequested {},
            Event::StopRequested {},
        ] {
            assert!(reopened.append(event, &KEY).is_err());
        }
        let recovering = reopened.append(Event::RecoveryRequested {}, &KEY).unwrap();
        assert_eq!(recovering.phase(), Phase::StopRequired);
        assert!(!recovering.recovery_required());
        assert!(recovering.append(Event::RemoveRequested {}, &KEY).is_err());
        assert_eq!(
            recovering.append(observed(), &KEY).unwrap().phase(),
            Phase::Stopped
        );
        // A second crash does not reuse the recovery transition as current evidence.
        assert!(restore(&recovering).recovery_required());
    }
}

#[test]
fn failed_transition_leaves_original_checkpoint_and_bytes_unchanged() {
    let journal = reserved();
    let before = journal.encode().unwrap();
    let checkpoint = journal.checkpoint();
    assert!(journal.append(boot(), &KEY).is_err());
    assert_eq!(journal.encode().unwrap(), before);
    assert_eq!(journal.checkpoint(), checkpoint);
}

#[test]
fn duplicate_create_boot_probe_stop_and_remove_are_not_replayed() {
    let created = reserved().append(Event::VmCreated {}, &KEY).unwrap();
    assert!(created.append(Event::VmCreated {}, &KEY).is_err());
    let running = created.append(boot(), &KEY).unwrap();
    assert!(running.append(boot(), &KEY).is_err());
    let probed = running
        .append(
            Event::InertProbeRecorded {
                response: fixture_response(&"66".repeat(32)).to_string(),
            },
            &KEY,
        )
        .unwrap();
    assert!(probed
        .append(
            Event::InertProbeRecorded {
                response: fixture_response(&"66".repeat(32)).to_string()
            },
            &KEY
        )
        .is_err());
    let stopping = probed.append(Event::StopRequested {}, &KEY).unwrap();
    assert!(stopping.append(Event::StopRequested {}, &KEY).is_err());
    let removing = stopping
        .append(observed(), &KEY)
        .unwrap()
        .append(Event::RemoveRequested {}, &KEY)
        .unwrap();
    assert!(removing.append(Event::RemoveRequested {}, &KEY).is_err());
}

#[test]
fn authenticated_chain_rejects_wrong_key_identity_reorder_and_mutations() {
    let journal = running();
    let bytes = journal.encode().unwrap();
    let checkpoint = journal.checkpoint();
    assert!(Journal::restore(&bytes, &identity(), &checkpoint, &[0x99; 32]).is_err());
    for field in ["installation", "job", "vmId", "imageSha256", "hostBoot"] {
        let mut expected = serde_json::to_value(identity()).unwrap();
        expected[field] = json!("00".repeat(if field == "imageSha256" { 32 } else { 16 }));
        let expected: Identity = serde_json::from_value(expected).unwrap();
        assert!(Journal::restore(&bytes, &expected, &checkpoint, &KEY).is_err());
    }
    for change in 0..5 {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        match change {
            0 => value["entries"][0]["mac"] = json!("00".repeat(32)),
            1 => value["entries"][1]["sequence"] = json!(7),
            2 => value["entries"][1]["previous"] = json!("00".repeat(32)),
            3 => value["entries"].as_array_mut().unwrap().swap(0, 1),
            _ => value["entries"][2]["event"]["challenge"] = json!("77".repeat(32)),
        }
        assert!(Journal::restore(
            &serde_json::to_vec(&value).unwrap(),
            &identity(),
            &checkpoint,
            &KEY
        )
        .is_err());
    }
}

#[test]
fn independent_checkpoint_detects_valid_prefix_rollback_and_tail_deletion() {
    let prefix = reserved();
    let final_journal = prefix.append(Event::VmCreated {}, &KEY).unwrap();
    assert!(Journal::restore(
        &prefix.encode().unwrap(),
        &identity(),
        &final_journal.checkpoint(),
        &KEY
    )
    .is_err());
    assert!(Journal::restore(
        &final_journal.encode().unwrap(),
        &identity(),
        &prefix.checkpoint(),
        &KEY
    )
    .is_err());
    let wrong = Checkpoint {
        sequence: 2,
        mac: "00".repeat(32),
    };
    assert!(Journal::restore(&final_journal.encode().unwrap(), &identity(), &wrong, &KEY).is_err());
}

#[test]
fn strict_parser_rejects_extra_duplicate_malformed_and_oversized_fields() {
    let journal = reserved();
    let bytes = journal.encode().unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    for path in 0..4 {
        let mut changed = value.clone();
        match path {
            0 => changed["command"] = json!("shell"),
            1 => changed["identity"]["key"] = json!("secret"),
            2 => changed["entries"][0]["event"]["target"] = json!("target"),
            _ => changed["entries"][0]["path"] = json!("/host"),
        }
        assert!(
            Journal::restore(
                &serde_json::to_vec(&changed).unwrap(),
                &identity(),
                &journal.checkpoint(),
                &KEY
            )
            .is_err(),
            "unknown-field case {path}"
        );
    }
    value["version"] = json!(2);
    let text = String::from_utf8(bytes).unwrap();
    for malformed in [
        text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
            .into_bytes(),
        serde_json::to_vec(&value).unwrap(),
        vec![],
        vec![b' '; MAX_JOURNAL_BYTES + 1],
        b"{}".to_vec(),
    ] {
        assert!(Journal::restore(&malformed, &identity(), &journal.checkpoint(), &KEY).is_err());
    }
}

#[test]
fn probe_must_match_active_challenge_and_cannot_promote_fixed_result() {
    for (field, changed) in [
        ("challenge", "77".repeat(32)),
        ("vmIsolation", "attested".into()),
        ("engineReadiness", "ready".into()),
        ("fixtureSha256", "00".repeat(32)),
    ] {
        let mut response = fixture_response(&"66".repeat(32));
        response[field] = json!(changed);
        assert!(running()
            .append(
                Event::InertProbeRecorded {
                    response: response.to_string()
                },
                &KEY
            )
            .is_err());
    }
    assert!(running()
        .append(
            Event::InertProbeRecorded {
                response: "a".repeat(1025)
            },
            &KEY
        )
        .is_err());
}

#[test]
fn bounded_recovery_history_fails_closed_without_dropping_old_events() {
    let mut journal = reserved();
    for _ in 1..MAX_EVENTS {
        journal = journal.append(Event::RecoveryRequested {}, &KEY).unwrap();
    }
    let before = journal.encode().unwrap();
    assert!(journal.append(Event::RecoveryRequested {}, &KEY).is_err());
    assert_eq!(journal.encode().unwrap(), before);
    assert_eq!(restore(&journal).checkpoint().sequence, MAX_EVENTS as u32);
}

#[test]
fn serialization_contains_no_boot_secret_and_whitespace_does_not_affect_mac() {
    let journal = running();
    let value: Value = serde_json::from_slice(&journal.encode().unwrap()).unwrap();
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert!(Journal::restore(&pretty, &identity(), &journal.checkpoint(), &KEY).is_ok());
    assert!(!String::from_utf8(pretty)
        .unwrap()
        .contains(&hex::encode(KEY)));
}

#[test]
fn wrong_append_key_cannot_poison_a_previously_valid_journal() {
    let journal = reserved();
    assert!(journal.append(Event::VmCreated {}, &[0x99; 32]).is_err());
    assert_eq!(restore(&journal).phase(), Phase::Reserved);
}

#[test]
fn every_event_rejects_unknown_fields_including_empty_struct_variants() {
    for event in [
        Event::Reserve {},
        Event::VmCreated {},
        boot(),
        Event::InertProbeRecorded {
            response: "{}".into(),
        },
        Event::StopRequested {},
        observed(),
        Event::RemoveRequested {},
        Event::RemovalObserved {
            vm_id: identity().vm_id,
        },
        Event::RecoveryRequested {},
    ] {
        let mut value = serde_json::to_value(event).unwrap();
        value["execute"] = json!("forbidden");
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
}

#[test]
fn valid_but_foreign_vm_and_boot_identity_are_not_admitted() {
    let journal = running();
    let mut foreign = identity();
    foreign.vm_id = "11223344-5566-7788-99aa-bbccddeeff01".into();
    assert!(Journal::restore(
        &journal.encode().unwrap(),
        &foreign,
        &journal.checkpoint(),
        &KEY
    )
    .is_err());
    foreign = identity();
    foreign.host_boot = "99".repeat(16);
    assert!(Journal::restore(
        &journal.encode().unwrap(),
        &foreign,
        &journal.checkpoint(),
        &KEY
    )
    .is_err());
}
