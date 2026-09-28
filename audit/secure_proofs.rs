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
    let root = std::env::temp_dir().join(format!("hacp-audit-{}", uuid::Uuid::new_v4()));
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
    Two { root, sa, sb, project }
}

fn run_hello_scenario(hellos: usize) -> (bool, Value) {
    let t = two();
    let mut ga = Guardian::load(&t.sa, &t.project, Mode::Degraded).unwrap();
    let mut gb = Guardian::load(&t.sb, &t.project, Mode::Degraded).unwrap();
    let open = br#"{"op":"open","hacp_session":"s-test"}"#;
    for _ in 0..hellos {
        let r = ga.handle_bytes(br#"{"op":"session","peer":"urn:hacp:agent:b","hacp_session":"s-test"}"#);
        assert_eq!(r["ok"], true, "{r}");
    }
    gb.handle_bytes(open); // B answers the hellos
    ga.handle_bytes(open); // A completes from acks
    let status = ga.handle_bytes(br#"{"op":"status"}"#);
    let sid = status["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["state"] == "Established")
        .expect("A established a session")["sid"]
        .as_str()
        .unwrap()
        .to_owned();
    let req = json!({"op":"seal","sid":sid,"contract":"","payload_b64":STANDARD.encode(b"canary")});
    let r = ga.handle_bytes(req.to_string().as_bytes());
    assert_eq!(r["ok"], true, "{r}");
    let mut delivered = false;
    let mut last = Value::Null;
    for _ in 0..5 {
        last = gb.handle_bytes(open);
        if last["delivered"].as_array().is_some_and(|d| !d.is_empty()) {
            delivered = true;
            break;
        }
    }
    (delivered, last)
}

#[test]
fn proof_four_hellos_control_delivers() {
    let (delivered, last) = run_hello_scenario(4);
    assert!(delivered, "control: {last}");
}

#[test]
fn proof_five_hellos_livelock_responder_never_keeps_session() {
    let (delivered, last) = run_hello_scenario(5);
    assert!(
        delivered,
        "BUG: with 5 hellos in the context B churns its AckSent sessions every open and never delivers. last open: {last}"
    );
}

#[test]
fn proof_fifo_session_json_hangs_guardian() {
    let fixture_root = std::env::temp_dir().join(format!("hacp-fifo-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&fixture_root).unwrap();
    let store = fixture_root.join("private");
    let project = fixture_root.join("project");
    fs::create_dir(&project).unwrap();
    initialize(&store, "urn:hacp:agent:a").unwrap();
    let mut g = Guardian::load(&store, &project, Mode::Degraded).unwrap();
    let mut b = SessionManager::new("urn:hacp:agent:b").unwrap();
    let h = g.manager.initiate("urn:hacp:agent:b", "s-test", &b.public_key()).unwrap();
    let ack = b.respond("s-test", &h, &g.manager.public_key()).unwrap();
    let sid = g.manager.complete("s-test", &ack).unwrap();
    // Hostile agent: arbitrary writes in the project dir.
    fs::create_dir(project.join(".hacp")).unwrap();
    let fifo = project.join(".hacp/session.json");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (tx, rx) = mpsc::channel();
    let req = json!({"op":"seal","sid":sid,"contract":"","payload_b64":""}).to_string();
    std::thread::spawn(move || {
        let r = g.handle_bytes(req.as_bytes());
        let _ = tx.send(r);
    });
    let outcome = rx.recv_timeout(Duration::from_secs(3));
    // Unblock the stuck reader so the test process can exit.
    let _w = OpenOptions::new().write(true).open(&fifo);
    drop(_w);
    let _ = fs::remove_dir_all(&fixture_root);
    assert!(
        outcome.is_ok(),
        "BUG: guardian request blocked >3s in open() of a FIFO at .hacp/session.json"
    );
}

#[test]
fn proof_fixed_window_admits_double_cap_within_one_second() {
    let fixture_root = std::env::temp_dir().join(format!("hacp-rate-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&fixture_root).unwrap();
    let store = fixture_root.join("private");
    let project = fixture_root.join("project");
    fs::create_dir(&project).unwrap();
    initialize(&store, "urn:hacp:agent:a").unwrap();
    let mut g = Guardian::load(&store, &project, Mode::Degraded).unwrap();
    g.set_rate_per_minute(3).unwrap();
    let probe = json!({"op":"fingerprint"}).to_string();
    // A window that began 59.7 s ago and is still unused (no clock mocking needed).
    let started = std::time::Instant::now();
    g.rate.window = Some((started.checked_sub(Duration::from_millis(59_700)).unwrap(), 0));
    let mut ok = 0;
    for _ in 0..3 {
        ok += (g.handle_bytes(probe.as_bytes())["ok"] == true) as u32;
    }
    std::thread::sleep(Duration::from_millis(400));
    for _ in 0..3 {
        ok += (g.handle_bytes(probe.as_bytes())["ok"] == true) as u32;
    }
    let elapsed = started.elapsed();
    let _ = fs::remove_dir_all(&fixture_root);
    assert!(
        ok <= 3,
        "BUG: {ok} requests admitted within {elapsed:?} under a cap of 3 per rolling minute"
    );
}

#[test]
fn proof_rate_limited_requests_still_append_audit_lines() {
    let fixture_root = std::env::temp_dir().join(format!("hacp-audit-log-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&fixture_root).unwrap();
    let store = fixture_root.join("private");
    let project = fixture_root.join("project");
    fs::create_dir(&project).unwrap();
    initialize(&store, "urn:hacp:agent:a").unwrap();
    let mut g = Guardian::load(&store, &project, Mode::Degraded).unwrap();
    g.set_rate_per_minute(1).unwrap();
    for _ in 0..5000 {
        g.handle_bytes(b"x");
    }
    let lines = fs::read_to_string(store.join("audit.jsonl")).unwrap().lines().count();
    let _ = fs::remove_dir_all(&fixture_root);
    assert!(lines <= 10, "BUG: {lines} audit lines written for 5000 requests under cap 1/min");
}

#[test]
fn proof_livelock_is_permanent_and_rehandshake_does_not_recover() {
    let t = two();
    let mut ga = Guardian::load(&t.sa, &t.project, Mode::Degraded).unwrap();
    let mut gb = Guardian::load(&t.sb, &t.project, Mode::Degraded).unwrap();
    let open = br#"{"op":"open","hacp_session":"s-test"}"#;
    let hello = br#"{"op":"session","peer":"urn:hacp:agent:b","hacp_session":"s-test"}"#;
    for _ in 0..5 { ga.handle_bytes(hello); }
    let sids = |g: &mut Guardian| -> Vec<String> {
        g.handle_bytes(br#"{"op":"status"}"#)["sessions"].as_array().unwrap().iter()
            .map(|s| s["sid"].as_str().unwrap().to_owned()).collect()
    };
    gb.handle_bytes(open);
    let b1 = sids(&mut gb);
    gb.handle_bytes(open);
    let b2 = sids(&mut gb);
    eprintln!("B sids after open1={b1:?}\nB sids after open2={b2:?}");
    assert!(b1.iter().all(|s| !b2.contains(s)), "every AckSent session replaced on each open");
    // Re-run: A starts a brand-new handshake (spec: evicted hello must re-run).
    for round in 0..3 {
        ga.handle_bytes(hello);
        gb.handle_bytes(open);
        ga.handle_bytes(open);
        let st = ga.handle_bytes(br#"{"op":"status"}"#);
        let est: Vec<String> = st["sessions"].as_array().unwrap().iter()
            .filter(|s| s["state"] == "Established").map(|s| s["sid"].as_str().unwrap().to_owned()).collect();
        for sid in &est {
            let req = json!({"op":"seal","sid":sid,"contract":"","payload_b64":STANDARD.encode(b"x")});
            ga.handle_bytes(req.to_string().as_bytes());
        }
        let mut got = 0;
        for _ in 0..3 { got += gb.handle_bytes(open)["delivered"].as_array().unwrap().len(); }
        let bs = sids(&mut gb);
        eprintln!("round {round}: A established={} B-has-any={} delivered={got}", est.len(), est.iter().any(|s| bs.contains(s)));
        assert_eq!(got, 0);
    }
}

#[test]
fn proof_schema_vs_code_ct_odd_and_ts_space() {
    let base = json!({"v":1,"kind":"msg","from":"urn:hacp:agent:a","to":"urn:hacp:agent:b","contract":"",
        "sid":"01".repeat(16),"seq":0,"sig":"02".repeat(64),"ct":"03".repeat(16)});
    let mut odd = base.clone();
    odd["ct"] = json!(format!("{}0", "03".repeat(16))); // 33 hex chars: matches schema ^[0-9a-f]{32,}$
    eprintln!("odd-length ct (schema-valid): {:?}", SecureEnvelope::from_json(odd.to_string().as_bytes()).err());
    let mut ts = base.clone();
    ts["ts"] = json!("2026-09-13 00:00:00Z"); // not RFC3339 date-time (space separator)
    eprintln!("space-separated ts: {:?}", SecureEnvelope::from_json(ts.to_string().as_bytes()).map(|_| "accepted"));
}
