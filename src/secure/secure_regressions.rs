use super::*;
use std::sync::mpsc;

struct Two {
    root: PathBuf,
    sa: PathBuf,
    sb: PathBuf,
    project: PathBuf,
}

impl Drop for Two {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn two() -> Two {
    let root = std::env::temp_dir().join(format!("hacp-s1-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let sa = root.join("a");
    let sb = root.join("b");
    let project = root.join("project");
    fs::create_dir(&project).unwrap();
    initialize(&sa, "urn:hacp:agent:a").unwrap();
    initialize(&sb, "urn:hacp:agent:b").unwrap();
    let pa = fs::read_to_string(sa.join("identity.pub")).unwrap();
    let pb = fs::read_to_string(sb.join("identity.pub")).unwrap();
    pin_peer(&sa, "urn:hacp:agent:b", &pb, true).unwrap();
    pin_peer(&sb, "urn:hacp:agent:a", &pa, true).unwrap();
    Two {
        root,
        sa,
        sb,
        project,
    }
}

fn run_hello_scenario(hellos: usize) -> (bool, Value) {
    let t = two();
    let mut ga = Guardian::load(&t.sa, &t.project, Mode::Degraded).unwrap();
    let mut gb = Guardian::load(&t.sb, &t.project, Mode::Degraded).unwrap();
    let open = br#"{"op":"open","hacp_session":"s-test"}"#;
    for _ in 0..hellos {
        let r = ga
            .handle_bytes(br#"{"op":"session","peer":"urn:hacp:agent:b","hacp_session":"s-test"}"#);
        assert_eq!(r["ok"], true, "{r}");
    }
    gb.handle_bytes(open);
    ga.handle_bytes(open);
    let status = ga.handle_bytes(br#"{"op":"status"}"#);
    let sids: Vec<String> = status["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["state"] == "Established")
        .map(|s| s["sid"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        !sids.is_empty(),
        "S1: initiator establishes despite five hello files"
    );
    // Each side may initially evict a different one of the five attempts
    // because immutable edge filenames sort independently of creation order.
    // At least three established candidates are shared; send on all candidates
    // and require that one of those surviving sessions delivers.
    for sid in sids {
        let req =
            json!({"op":"seal","sid":sid,"contract":"","payload_b64":STANDARD.encode(b"canary")});
        let r = ga.handle_bytes(req.to_string().as_bytes());
        assert_eq!(r["ok"], true, "{r}");
    }
    let mut last = Value::Null;
    for _ in 0..5 {
        last = gb.handle_bytes(open);
        if last["delivered"]
            .as_array()
            .is_some_and(|delivered| !delivered.is_empty())
        {
            return (true, last);
        }
    }
    (false, last)
}

#[test]
fn s1_five_hellos_session_survives() {
    let (delivered, last) = run_hello_scenario(5);
    assert!(
        delivered,
        "S1: five hello files must not livelock the responder; last open: {last}"
    );
}

#[test]
fn s1_repeated_scans_are_idempotent_and_rehandshake_recovers() {
    let t = two();
    let mut ga = Guardian::load(&t.sa, &t.project, Mode::Degraded).unwrap();
    let mut gb = Guardian::load(&t.sb, &t.project, Mode::Degraded).unwrap();
    let open = br#"{"op":"open","hacp_session":"s-test"}"#;
    let hello = br#"{"op":"session","peer":"urn:hacp:agent:b","hacp_session":"s-test"}"#;
    for _ in 0..5 {
        assert_eq!(ga.handle_bytes(hello)["ok"], true);
    }
    gb.handle_bytes(open);
    let first: Vec<String> = gb.manager.sessions().into_iter().map(|s| s.sid).collect();
    gb.handle_bytes(open);
    let second: Vec<String> = gb.manager.sessions().into_iter().map(|s| s.sid).collect();
    assert_eq!(
        first, second,
        "S1: rescanning immutable hellos must not replace AckSent sessions"
    );

    ga.handle_bytes(open);
    let before: BTreeSet<String> = ga.manager.sessions().into_iter().map(|s| s.sid).collect();
    assert_eq!(ga.handle_bytes(hello)["ok"], true);
    gb.handle_bytes(open);
    ga.handle_bytes(open);
    let established = ga.manager.sessions().into_iter().any(|s| {
        !before.contains(&s.sid)
            && s.hacp_session == "s-test"
            && s.state == "Established"
            && gb.manager.info(&s.sid).is_ok()
    });
    assert!(
        established,
        "S1: a fresh handshake must recover after the bounded pending set evicts older attempts"
    );
}

#[test]
fn s2_fifo_session_json_is_rejected_without_blocking() {
    let fixture_root = std::env::temp_dir().join(format!("hacp-s2-fifo-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&fixture_root).unwrap();
    let store = fixture_root.join("private");
    let project = fixture_root.join("project");
    fs::create_dir(&project).unwrap();
    initialize(&store, "urn:hacp:agent:a").unwrap();
    let mut g = Guardian::load(&store, &project, Mode::Degraded).unwrap();
    let mut b = SessionManager::new("urn:hacp:agent:b").unwrap();
    let h = g
        .manager
        .initiate("urn:hacp:agent:b", "s-test", &b.public_key())
        .unwrap();
    let ack = b.respond("s-test", &h, &g.manager.public_key()).unwrap();
    let sid = g.manager.complete("s-test", &ack).unwrap();
    fs::create_dir(project.join(".hacp")).unwrap();
    let fifo = project.join(".hacp/session.json");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (tx, rx) = mpsc::channel();
    let req = json!({"op":"seal","sid":sid,"contract":"","payload_b64":""}).to_string();
    std::thread::spawn(move || {
        let _ = tx.send(g.handle_bytes(req.as_bytes()));
    });
    let response = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("S2: FIFO session.json must not block guardian open(2)");
    assert_eq!(
        response["error"], "ContractMismatch",
        "S2: non-regular session.json must fail closed"
    );
    let _ = fs::remove_dir_all(&fixture_root);
}
