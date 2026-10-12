//! End-to-end matrix against a SYNTHETIC iSCSI target server
//! (v0.9.0, Phase 4): a loopback TCP listener speaking enough of
//! RFC 3720 to exercise the initiator's discovery, login and SCSI
//! passthrough paths — including the deadline fail-safe against a
//! silent target.

use dc_hw::{ScsiCodec, ScsiSanitizeServiceAction};
use dc_iscsi::bhs::{
    Bhs, FLAG_FINAL, OP_DATA_IN, OP_LOGIN_REQ, OP_LOGIN_RSP, OP_LOGOUT_REQ, OP_LOGOUT_RSP,
    OP_SCSI_CMD, OP_SCSI_RSP, OP_TEXT_REQ, OP_TEXT_RSP, Pdu, read_pdu,
};
use dc_iscsi::login::TextParam;
use dc_iscsi::session::{DiscoveredTarget, IscsiSession, Portal};
use dc_iscsi::{IscsiError, IscsiTimeouts, ScsiIoParams};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn login_ok_rsp() -> Pdu {
    let mut bhs = [0u8; 48];
    bhs[0] = OP_LOGIN_RSP;
    bhs[1] = 0x80 | 0x04 | (3 << 3); // F + T + NSG=3 (full feature phase)
    bhs[36] = 0; // status class 0 (success)
    let data = TextParam::encode(&[TextParam::new("AuthMethod", "None")]);
    let len = data.len();
    bhs[5] = (len >> 16) as u8;
    bhs[6] = (len >> 8) as u8;
    bhs[7] = len as u8;
    Pdu {
        bhs: Bhs(bhs),
        data,
    }
}

fn text_rsp(params: &[TextParam]) -> Pdu {
    let mut bhs = [0u8; 48];
    bhs[0] = OP_TEXT_RSP;
    bhs[1] = FLAG_FINAL;
    let data = TextParam::encode(params);
    let len = data.len();
    bhs[5] = (len >> 16) as u8;
    bhs[6] = (len >> 8) as u8;
    bhs[7] = len as u8;
    Pdu {
        bhs: Bhs(bhs),
        data,
    }
}

/// The stock SAN behavior: negotiate, answer SendTargets, echo INQUIRY,
/// ACK SANITIZE, refuse everything else with ILLEGAL REQUEST.
fn san_behavior(bhs: &Bhs, data: &[u8]) -> Vec<Pdu> {
    match bhs.opcode() {
        OP_LOGIN_REQ => vec![login_ok_rsp()],
        OP_TEXT_REQ => {
            let req = TextParam::parse_all(data);
            if req.iter().any(|p| p.key == "SendTargets") {
                vec![text_rsp(&[
                    TextParam::new("TargetName", "iqn.2000-01.com.example:san"),
                    TextParam::new("TargetAddress", "127.0.0.1:3260,1"),
                    TextParam::new("TargetName", "iqn.2000-01.com.example:archive"),
                    TextParam::new("TargetAddress", "[::1]:3260,2"),
                ])]
            } else {
                vec![text_rsp(&[])]
            }
        }
        OP_SCSI_CMD => {
            let cdb = &bhs.0[32..48];
            match cdb[0] {
                0x12 => {
                    // INQUIRY: standard 36-byte identity page.
                    let mut page = [0u8; 36];
                    page[0] = 0x00; // direct-access device
                    page[2] = 0x06; // SPC-4
                    page[4] = 32; // additional length
                    page[8..16].copy_from_slice(b"DCSYNTH ");
                    page[16..32].copy_from_slice(b"ISCSI-TGT-TEST-1");
                    page[32..36].copy_from_slice(b"0.90");
                    let mut din = [0u8; 48];
                    din[0] = OP_DATA_IN;
                    din[7] = page.len() as u8;
                    let mut rsp = [0u8; 48];
                    rsp[0] = OP_SCSI_RSP;
                    rsp[1] = FLAG_FINAL;
                    vec![
                        Pdu {
                            bhs: Bhs(din),
                            data: page.to_vec(),
                        },
                        Pdu {
                            bhs: Bhs(rsp),
                            data: Vec::new(),
                        },
                    ]
                }
                0x48 => {
                    // SANITIZE: ACK with GOOD status.
                    let mut rsp = [0u8; 48];
                    rsp[0] = OP_SCSI_RSP;
                    rsp[1] = FLAG_FINAL;
                    vec![Pdu {
                        bhs: Bhs(rsp),
                        data: Vec::new(),
                    }]
                }
                _ => {
                    // CHECK CONDITION with ILLEGAL REQUEST sense.
                    let mut sense = vec![0u8; 14];
                    sense[0] = 0x70;
                    sense[2] = 0x05; // ILLEGAL REQUEST
                    sense[12] = 0x20; // invalid command operation code
                    let mut rsp = [0u8; 48];
                    rsp[0] = OP_SCSI_RSP;
                    rsp[1] = FLAG_FINAL;
                    rsp[3] = 0x02; // CHECK CONDITION
                    let len = sense.len();
                    rsp[7] = len as u8;
                    vec![Pdu {
                        bhs: Bhs(rsp),
                        data: sense,
                    }]
                }
            }
        }
        OP_LOGOUT_REQ => {
            let mut rsp = [0u8; 48];
            rsp[0] = OP_LOGOUT_RSP;
            rsp[1] = FLAG_FINAL;
            rsp[2] = 0; // response: command completed
            vec![Pdu {
                bhs: Bhs(rsp),
                data: Vec::new(),
            }]
        }
        _ => vec![],
    }
}

fn spawn(
    mut behavior: impl FnMut(&Bhs, &[u8]) -> Vec<Pdu> + Send + 'static,
) -> (Portal, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        while let Ok(pdu) = read_pdu(&mut stream, Duration::from_secs(5)) {
            let replies = behavior(&pdu.bhs, &pdu.data);
            if replies.is_empty() {
                break;
            }
            for mut out in replies {
                // Mirror the ITT like a compliant target.
                out.bhs.0[16..20].copy_from_slice(&pdu.bhs.0[16..20]);
                let _ = stream.write_all(&out.bhs.0);
                if !out.data.is_empty() {
                    let _ = stream.write_all(&out.data);
                    let pad = (4 - (out.data.len() % 4)) % 4;
                    let _ = stream.write_all(&[0u8; 4][..pad]);
                }
            }
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    (
        Portal {
            host: "127.0.0.1".into(),
            port,
        },
        handle,
    )
}

#[test]
fn discovery_login_sendtargets_logout_ladder() {
    let (portal, server) = spawn(san_behavior);
    let targets = IscsiSession::discover(&portal, IscsiTimeouts::default()).expect("discover");
    assert_eq!(targets.len(), 2, "both advertised targets must parse");
    assert_eq!(
        targets[0],
        DiscoveredTarget {
            target_name: "iqn.2000-01.com.example:san".into(),
            addresses: vec![("127.0.0.1".into(), 3260, 1)],
        }
    );
    assert_eq!(targets[1].addresses[0].0, "::1");
    server.join().expect("server thread clean");
}

#[test]
fn operational_login_and_scsi_passthrough() {
    let (portal, server) = spawn(san_behavior);
    let mut session = IscsiSession::login_target(
        &portal,
        "iqn.2000-01.com.example:san",
        "iqn.2014-08.org.discleaner:test-initiator",
        IscsiTimeouts::default(),
    )
    .expect("operational login");
    assert_eq!(session.session_type, "Normal");

    // INQUIRY through the session: 36-byte identity page.
    let mut cdb = [0u8; 16];
    cdb[..6].copy_from_slice(&ScsiCodec::encode_inquiry(36));
    let inquiry = ScsiIoParams::read(0, cdb, 6, 36, Duration::from_secs(5));
    let out = session.execute(&inquiry).expect("inquiry exchange");
    assert!(out.is_good(), "INQUIRY must complete GOOD: {:?}", out.sense);
    assert_eq!(out.data_in.len(), 36);
    assert_eq!(&out.data_in[8..16], b"DCSYNTH ");

    // SANITIZE (crypto erase) through the session.
    let sanitize = ScsiIoParams::write(
        0,
        ScsiCodec::encode_sanitize(ScsiSanitizeServiceAction::CryptoErase, true),
        16,
        Duration::from_secs(5),
    );
    let out = session.execute(&sanitize).expect("sanitize exchange");
    assert!(out.is_good(), "SANITIZE must be ACKed GOOD");
    assert!(out.sense.is_none());

    session.logout().expect("logout");
    server.join().expect("server thread clean");
}

#[test]
fn illegal_command_surfaces_sense_data() {
    let (portal, server) = spawn(san_behavior);
    let mut session = IscsiSession::login_target(
        &portal,
        "iqn.2000-01.com.example:san",
        "iqn.2014-08.org.discleaner:test-initiator",
        IscsiTimeouts::default(),
    )
    .expect("login");

    // TEST UNIT READY (0x00): the synthetic target refuses it.
    let cdb = [0u8; 16];
    let probe = ScsiIoParams::write(0, cdb, 6, Duration::from_secs(5));
    let out = session.execute(&probe).expect("exchange");
    assert_eq!(out.status, 0x02, "CHECK CONDITION expected");
    let sense = out.sense.expect("sense must be carried");
    assert_eq!(sense.sense_key, 0x05);
    assert_eq!(sense.asc, 0x20);

    let _ = session.logout();
    server.join().expect("server thread clean");
}

#[test]
fn silent_target_hits_the_deadline_not_a_hang() {
    // A target that accepts the TCP connection and then says NOTHING.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut sink = [0u8; 64];
        while let Ok(n) = stream.read(&mut sink) {
            if n == 0 {
                break;
            }
        }
    });
    let portal = Portal {
        host: "127.0.0.1".into(),
        port,
    };
    let started = std::time::Instant::now();
    let err = IscsiSession::discover(
        &portal,
        IscsiTimeouts {
            login_ms: 750,
            scsi_ms: 750,
        },
    );
    assert!(
        matches!(
            err,
            Err(IscsiError::Timeout(_)) | Err(IscsiError::Transport(_))
        ),
        "silent target must fail the deadline: got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the deadline guard must bound the failure time"
    );
}
