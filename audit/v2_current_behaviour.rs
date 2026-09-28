//! Audit proofs. Each test asserts the CURRENT (defective) behavior, so a
//! passing test means the defect is present.

use hacp::v2::canon::canonical_json;
use hacp::v2::*;
use serde_json::{json, Value};

const T0: &str = "2026-09-05T00:00:00Z";
const T1: &str = "2026-09-06T00:00:00Z";
const T2: &str = "2026-09-07T00:00:00Z";

fn u(n: &str) -> String {
    format!("urn:hacp:agent:{n}")
}

fn org() -> OrgChart {
    let mut org = OrgChart::default();
    for (c, p) in [("p1", "root"), ("p2", "root"), ("c1", "p1"), ("c2", "p1"), ("c3", "p2")] {
        org.parent_of.insert(u(c), u(p));
    }
    org
}

// ---- 1. preauthorization never checks the peer ---------------------------
#[test]
fn preauth_permit_reaches_a_peer_outside_the_grantors_authority() {
    let org = org();
    let mut l = GrantLedger::default();
    l.issue(
        CapabilityGrant::charter(
            "g-000000000010",
            &u("deployment"),
            &u("p1"),
            vec![ScopeElement { name: "cross-branch/review".into(), delegable: true }],
            T0,
            T2,
        )
        .unwrap(),
        T0,
    )
    .unwrap();
    HiveProfile
        .authorize_siblings(&mut l, &org, &u("p1"), &u("c1"), "review", "g-000000000011", T0, T2)
        .unwrap();
    for peer in [u("c3"), u("root"), u("stranger-not-in-org")] {
        let req = CollaborationRequest {
            request_id: "cr-000000000001".into(),
            requester: u("c1"),
            peer: peer.clone(),
            task_class: "review".into(),
            expires: T1.into(),
        };
        let permit = CollaborationPermit::by_preauthorization(&l, &req, T0).unwrap();
        permit
            .authorize_session(&org, &l, &u("c1"), &peer, "review", T0)
            .unwrap();
        println!("c1 <-> {peer}: permit {} admitted", permit.permit_id);
    }
}

// ---- 2. one party alone drives a frozen contract to NoAgreement ------------
fn executing() -> (Contract, String) {
    let mut s = Session::open("s-audit", &u("parent"), &u("child")).unwrap();
    s.accept(&u("child")).unwrap();
    let mut c = Contract::propose(
        &s,
        "c-audit",
        Task { task_id: "t".into(), summary: "s".into(), owner: u("child") },
        Relationship::Delegation,
        vec![u("parent")],
        ContractLimits { max_rounds: 3, max_amendments: 2 },
    )
    .unwrap();
    let terms = json!({"output": "one line"});
    c.agree(&u("parent"), &terms).unwrap();
    c.agree(&u("child"), &terms).unwrap();
    let d = c.freeze(terms).unwrap();
    (c, d)
}

#[test]
fn one_party_unilaterally_exits_a_frozen_contract_via_amendment_counters() {
    let (mut c, _) = executing();
    let child = u("child");
    c.propose_amendment(&child).unwrap();
    c.counter(&child).unwrap();
    c.counter(&child).unwrap();
    let r = c.counter(&child);
    println!("third self-counter: {r:?}; state {:?}", c.state);
    assert_eq!(c.state, ContractState::NoAgreement);
    assert_eq!(c.revisions.len(), 1, "a frozen rev-1 contract was live");
    // Parent never acted after freeze. Compare: withdraw is refused post-freeze.
    let (mut c2, _) = executing();
    assert!(c2.withdraw(&child).is_err());
    // Even simpler: expire_negotiation from Amending (one-sided proposal).
    c2.propose_amendment(&child).unwrap();
    c2.expire_negotiation().unwrap();
    assert_eq!(c2.state, ContractState::NoAgreement);
}

#[test]
fn performer_escapes_rework_via_self_countered_amendment() {
    let (mut c, d) = executing();
    c.submit(
        &u("child"),
        Submission { against_revision: d, artifacts: vec!["x".into()], evidence: vec![], claim: "done".into() },
    )
    .unwrap();
    c.decide(Verdict::Rework { scope: "fix it".into() }).unwrap();
    c.propose_amendment(&u("child")).unwrap();
    for _ in 0..3 {
        let _ = c.counter(&u("child"));
    }
    assert_eq!(c.state, ContractState::NoAgreement);
}

// ---- 3. escalation ladder never leaves the first mediator ------------------
#[test]
fn referral_never_moves_above_the_shared_parent() {
    let org = org();
    let (mut e, m) = Escalation::raise(
        &org,
        "esc-000000000001",
        &u("c1"),
        &u("c2"),
        EscalationSubject::Task { task_id: "t".into() },
        T0,
    )
    .unwrap();
    e.refer(&org).unwrap();
    println!("raised mediator {m}; referred mediator {:?}", e.mediator);
    assert_eq!(e.mediator.as_deref(), Some(m.as_str()));
    assert_eq!(e.stage, EscalationStage::Referred);
}

#[test]
fn delegation_parties_cannot_raise_but_self_dispute_can() {
    let org = org();
    let r = Escalation::raise(
        &org,
        "esc-000000000002",
        &u("p1"),
        &u("c1"),
        EscalationSubject::Contract { contract_id: "c".into() },
        T0,
    );
    println!("parent/child raise: {:?}", r.as_ref().err());
    assert!(matches!(r, Err(EscalationError::NotSameParent(..))));
    let (e, _) = Escalation::raise(
        &org,
        "esc-000000000003",
        &u("c1"),
        &u("c1"),
        EscalationSubject::Task { task_id: "t".into() },
        T0,
    )
    .unwrap();
    assert_eq!(e.parties[0], e.parties[1]);
}

// ---- 4. agreed amendment at the bound kills the contract -------------------
#[test]
fn mutually_agreed_amendment_at_bound_is_no_agreement() {
    let (mut c, _) = executing(); // max_amendments = 2
    for i in 0..3 {
        c.propose_amendment(&u("parent")).unwrap(); // never refused at the bound
        let t = json!({"output": format!("v{i}")});
        c.decide_amendment(&u("parent"), true, Some(t.clone())).unwrap();
        let r = c.decide_amendment(&u("child"), true, Some(t));
        println!("amendment {i}: {r:?} -> {:?}", c.state);
    }
    assert_eq!(c.state, ContractState::NoAgreement);
    assert_eq!(c.revisions.len(), 3);
}

// ---- 5. canonical form: integer range differs from the independent peer ----
#[test]
fn canonical_refuses_integers_the_spec_and_python_peer_accept() {
    for raw in ["-0", "18446744073709551616", "-9223372036854775809"] {
        let v: Value = serde_json::from_str(raw).unwrap();
        let r = canonical_json(&v);
        println!("{raw} -> {r:?}");
        assert!(r.is_err());
    }
    // Same thing inside contract terms: agreement on valid-looking terms fails.
    let (mut s, _) = (Session::open("s-x", &u("a"), &u("b")).unwrap(), ());
    s.accept(&u("b")).unwrap();
    let mut c = Contract::propose(
        &s,
        "c-x",
        Task { task_id: "t".into(), summary: "s".into(), owner: u("b") },
        Relationship::Collaboration,
        vec![],
        ContractLimits { max_rounds: 2, max_amendments: 1 },
    )
    .unwrap();
    let terms: Value = serde_json::from_str(r#"{"budget_bytes": 18446744073709551616}"#).unwrap();
    assert!(matches!(c.agree(&u("a"), &terms), Err(ContractError::NotCanonical(_))));
}

// ---- low items -------------------------------------------------------------
#[test]
fn low_items() {
    // charter doc says "deployment" is a valid charterer
    assert!(CapabilityGrant::charter(
        "g-000000000001",
        "deployment",
        &u("a"),
        vec![],
        T0,
        T1
    )
    .is_err());
    // the profile id cannot be advertised as an Agent capability
    assert!(Agent::with_capabilities(&u("a"), &[HIVE_PROFILE]).is_err());
    // in_reply_to: null is dropped on re-serialization
    let raw = json!({
        "protocol": "HACP/2.0", "message_id": "m-000000000000", "session_id": "s",
        "from": u("a"), "to": u("b"), "kind": "heartbeat",
        "timestamp": "2026-09-04T12:00:00Z", "in_reply_to": null, "body": {}
    });
    let e: Envelope = serde_json::from_value(raw.clone()).unwrap();
    e.validate().unwrap();
    assert_ne!(serde_json::to_value(&e).unwrap(), raw);
    // verdict wire strings vs spec prose "accepted | rework | rejected"
    assert!(serde_json::from_value::<Verdict>(json!("accepted")).is_err());
}
