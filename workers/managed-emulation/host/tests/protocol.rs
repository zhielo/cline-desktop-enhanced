use cline_managed_inert_probe::*;
use serde_json::{json, Value};
use std::io::Cursor;

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const SESSION: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
fn challenge() -> String {
    "ab".repeat(32)
}
fn vector() -> Value {
    serde_json::from_str(include_str!("../../protocol-vectors.json")).unwrap()
}

#[test]
fn matches_python_request_and_accepts_python_response() {
    let v = vector();
    let request = encode_frame(
        &KEY,
        &SESSION,
        1,
        &ProbeRequest {
            operation: "owned-probe",
            challenge: &challenge(),
        },
    )
    .unwrap();
    assert_eq!(
        hex::encode(&request),
        v["requestFrameHex"].as_str().unwrap()
    );
    let response = hex::decode(v["responseFrameHex"].as_str().unwrap()).unwrap();
    let body = receive_frame(&mut Cursor::new(response), &KEY, &SESSION, 2).unwrap();
    let result = verify_response(&body, &challenge()).unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap()["engineReadiness"],
        "not-tested"
    );
}

#[test]
fn rejects_wrong_key_session_direction_and_modified_mac() {
    let mut frame = hex::decode(vector()["responseFrameHex"].as_str().unwrap()).unwrap();
    assert!(receive_frame(&mut Cursor::new(&frame), &[255; 32], &SESSION, 2).is_err());
    assert!(receive_frame(&mut Cursor::new(&frame), &KEY, &[255; 16], 2).is_err());
    assert!(receive_frame(&mut Cursor::new(&frame), &KEY, &SESSION, 1).is_err());
    let at = frame.len() - 3;
    frame[at] = if frame[at] == b'0' { b'1' } else { b'0' };
    assert!(receive_frame(&mut Cursor::new(&frame), &KEY, &SESSION, 2).is_err());
}

#[test]
fn rejects_oversized_and_truncated_frames_without_allocation_from_untrusted_length() {
    for bytes in [
        vec![],
        vec![0],
        vec![0; 4],
        ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec(),
        u32::MAX.to_be_bytes().to_vec(),
        vec![0, 0, 0, 12, b'{'],
    ] {
        assert!(receive_frame(&mut Cursor::new(bytes), &KEY, &SESSION, 2).is_err());
    }
}

#[test]
fn rejects_unknown_and_duplicate_fields() {
    for body in [
        r#"{"protocol":"x","session":"","sequence":2,"payload":"","mac":"","extra":1}"#,
        r#"{"protocol":"x","session":"","sequence":2,"sequence":2,"payload":"","mac":""}"#,
    ] {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend(body.as_bytes());
        assert!(receive_frame(&mut Cursor::new(frame), &KEY, &SESSION, 2).is_err());
    }
}

#[test]
fn response_cannot_promote_readiness_or_isolation_or_change_challenge() {
    for (field, value) in [
        ("vmIsolation", json!("verified")),
        ("engineReadiness", json!("ready")),
        ("execution", json!("native-target")),
        ("challenge", json!("cd".repeat(32))),
        ("fixtureSha256", json!("00".repeat(32))),
        ("extra", json!(true)),
    ] {
        let mut response = fixture_response(&challenge());
        response[field] = value;
        assert!(verify_response(&serde_json::to_vec(&response).unwrap(), &challenge()).is_err());
    }
}

#[test]
fn encodes_exact_windows_and_linux_service_guid_byte_order() {
    let address = hyperv_address("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    assert_eq!(
        hex::encode(address),
        "2200000067452301ab89efcd0123456789abcdefe38a0000cbfae611bd5864006a7986d3"
    );
    assert_eq!(PORT, 35555);
}

#[test]
fn rejects_wildcard_parent_loopback_children_and_malformed_vm_identities() {
    for vm in [
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd",
        "e0e16197-dd56-4a10-9195-5ee7a155a838",
        "a42e7cda-d03f-480c-9cc2-a4de20abb878",
        "",
        "http://host",
        "../../vm",
        "01234567-89ab-cdef-0123-456789abcdeG",
    ] {
        assert!(hyperv_address(vm).is_err());
    }
}

#[test]
fn hex_keys_and_sequences_are_exact_and_payloads_bounded() {
    for value in [
        "".to_owned(),
        "AA".repeat(32),
        "a".repeat(63),
        "a".repeat(65),
    ] {
        assert!(exact_hex::<32>(&value).is_err());
    }
    assert!(encode_frame(&KEY, &SESSION, 0, &json!({})).is_err());
    assert!(encode_frame(&KEY, &SESSION, 1, &json!({"large": "a".repeat(1025)})).is_err());
}
