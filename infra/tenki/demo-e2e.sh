#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != --dry-run ]; then
  set -a
  . "$(dirname "$0")/common.sh"
  set +a
fi
python3 - "$(dirname "$0")" "$@" <<'PY'
import ast, base64, json, os, pathlib, shlex, subprocess, sys, threading, time
D = pathlib.Path(sys.argv[1]).resolve()
if sys.argv[2:] == ['--dry-run']:
    for f in [*D.glob('*.sh'), *D.glob('lib/*.sh')]:
        subprocess.run(['bash', '-n', str(f)], check=True)
    assert 'hacp-exec-guardian' in (D/'demo-e2e.sh').read_text()
    print('DRY RUN PASS: create -> bootstrap -> deploy -> pin -> standard guardians -> secure /hacp freeze -> Wasmer -> settlement -> replay/tamper -> cleanup')
    sys.exit(0)
if sys.argv[2:]: raise SystemExit('usage: demo-e2e.sh [--dry-run]')
P = os.environ['HACP_PROJECT_DIR']; AH = os.environ['HACP_AGENT_HOME']
GH = os.environ['HACP_GUARDIAN_HOME']; GU = os.environ['HACP_GUARDIAN_USER']
STATE = pathlib.Path(os.environ['HACP_STATE_DIR']); PACKAGE = os.environ['HACP_WASMER_PACKAGE']
CACHE = os.environ['HACP_EXEC_WASMER_DIR']; POLICY = os.environ['HACP_EXEC_POLICY']
AUDIT = os.environ['HACP_EXEC_AUDIT']; STAGING = os.environ['HACP_EXEC_STAGING']
URNS = {p: os.environ['HACP_PEER_'+p.upper()+'_URN'] for p in 'ab'}
SOCKET = {p: f'{GH}/runtime/{p}/guardian.sock' for p in 'ab'}
assert not json.loads((STATE/'sessions.json').read_text()), 'refuse to reuse or replace existing recorded VMs'
aliases = {}; resources = {}; results = {}; sync_process = None

def local(args, capture=False):
    r = subprocess.run(list(map(str,args)), text=True, capture_output=capture)
    if r.returncode: raise RuntimeError(f'command failed: {args[0]} (exit {r.returncode})\n'+(r.stderr or '')[-2000:])
    return r.stdout

def remote(p, code, agent=False, check=True):
    if agent:
        env = ['HOME='+AH, 'PATH=/usr/local/bin:/usr/bin:/bin', 'HACP_SECURE=1',
               'HACP_SECURE_SOCKET='+SOCKET[p], 'HACP_SECURE_STATE='+AH+'/.hacp-agent-state']
        code = shlex.join(['sudo','-u','hacp-agent','env','-i',*env,'bash','-c',f'umask 022; cd {shlex.quote(P)}; '+code])
    r = subprocess.run(['ssh',aliases[p],code],text=True,capture_output=True)
    if check and r.returncode: raise RuntimeError(f'peer {p} command exit {r.returncode}: {r.stderr[-2000:]} {r.stdout[-2000:]}')
    return r

def put(p, path, value, agent=True):
    data = value if isinstance(value,str) else json.dumps(value)
    code = 'import pathlib,base64; p=pathlib.Path('+repr(path)+');p.write_bytes(base64.b64decode('+repr(base64.b64encode(data.encode()).decode())+'))'
    remote(p, shlex.join(['python3','-c',code]), agent=agent)

def skill(p,*args):
    r=remote(p,shlex.join(['hacp','--peer',p,'--project',P,'--json',*args]),agent=True)
    # The Guardian reads the cooperative contract snapshot, never private skill receipts.
    remote(p,shlex.join(['sudo','setfacl','-R','-m','u:'+GU+':rX',P+'/.hacp']))
    return json.loads(r.stdout)

def sync(p=None):
    # sync-edge.sh --once; mutable cooperative state has one writer per turn.
    local([D/'sync-edge.sh','--once',*(['--from',p] if p else ['--edge-only'])],True)

def client(*flags):
    # hacp-exec --socket ... --contract ... returns the sealed ExecutionResult.
    return json.loads(remote('a',shlex.join(['hacp-exec','--socket',SOCKET['a'],'--agent',URNS['a'],
       '--peer',URNS['b'],'--context',context,'--contract',binding,'--wait-secs','120',*flags]),agent=True).stdout)

def guest(name,*args,extra=()):
    flags=['--package',PACKAGE,'--file',name+'='+P+'/infra/wasmer/examples/'+name,'--arg','/work/'+name]
    for arg in args: flags += ['--arg',str(arg)]
    out=client(*flags,*extra); assert out['ok'],out
    returned=out['returned']; assert returned['contract']==binding,returned
    return returned

def safe_guest(returned):
    b=returned['body']
    assert b['status']=='completed' and b['exit_code']==0 and 'DONE' in b['stdout'].splitlines(),b
    assert not any(x.startswith('EXPOSED') for x in b['stdout'].splitlines()),b

def start_service(once=False):
    args=['env','WASMER_DIR='+CACHE,'HACP_WASMER_BIN=/usr/local/bin/wasmer',
          'HACP_GUARDIAN_PRIVATE_KEY=FAKE-guardian-canary','HACP_SESSION_KEY=FAKE-session-canary','WASMER_TOKEN=FAKE-token-canary',
          'hacp-exec-guardian','--socket',SOCKET['b'],'--agent',URNS['b'],'--context',context,
          '--policy',POLICY,'--audit',AUDIT,'--staging-root',STAGING,'--poll-ms','250']
    if once:
        return [json.loads(x) for x in remote('b',shlex.join(args+['--once']),agent=True).stdout.splitlines()]
    remote('b','setsid '+shlex.join(args)+' >'+shlex.quote(AH+'/exec-service.log')+' 2>&1 </dev/null &',agent=True)
    for _ in range(100):
        if remote('b','grep -q ready '+shlex.quote(AH+'/exec-service.log'),agent=True,check=False).returncode==0: return
        time.sleep(.1)
    raise RuntimeError('execution service did not become ready')

def stop_service():
    # Equivalent to pkill -f hacp-exec-guardian, narrowed to the exact service argv.
    remote('b',"pkill -f '^hacp-exec-guardian ' || test $? = 1",agent=True)

def stop_sync():
    global sync_process
    if sync_process:
        sync_process.terminate(); sync_process.wait(timeout=15); sync_process=None

try:
    for p in 'ab':
        local([D/'create-peer.sh',p])
        resources[p]=json.loads((STATE/'sessions.json').read_text())[p]['session_id']
        aliases[p]='sbx-'+resources[p]
    (STATE/'resources.json').write_text(json.dumps(resources,indent=2))
    print('TENKI RESOURCES '+json.dumps(resources),flush=True)
    # Sequential provisioning keeps local resource bookkeeping atomic.
    for p in 'ab':
        local([D/'bootstrap-peer.sh',p]); local([D/'deploy-hacp.sh',p])
        local([D/'guardian.sh',p,'init'])
    pubs={p:local([D/'guardian.sh',p,'public'],True).strip() for p in 'ab'}
    for p,other in [('a','b'),('b','a')]:
        local([D/'guardian.sh',p,'pin',URNS[other],pubs[other]])
        local([D/'guardian.sh',p,'start'])
        check=remote(p, 'test ! -r '+shlex.quote(GH+'/.hacp-secure/identity.json')+' && ! sudo -n true 2>/dev/null',agent=True)
        assert check.returncode==0
        remote(p,'wasmer --version',agent=True)
    print('STANDARD GUARDIANS PASS: non-sudo agent UID, private stores, pinned public identities',flush=True)
    skill('a','start','request sandbox execution','--owns','exec-result.json');sync('a')
    skill('b','join','verify sandbox execution','--owns','exec-review.txt');sync('b')
    skill('a','poll');sync('a');skill('b','poll');sync('b')
    contracts={}
    for p,other,output in [('a','b','exec-result.json'),('b','a','exec-review.txt')]:
        terms={'inputs':[],'outputs':[output],'acceptance':['test -s '+output]}
        path=AH+'/'+p+'-terms.json';put(p,path,terms)
        proposed=skill(p,'propose','--terms',path);sync(p)
        cid=proposed['contract']['contract_id']
        polled=skill(other,'poll'); assert any(m['kind']=='contract.proposed' for m in polled['messages']);sync(other)
        frozen=skill(other,'accept',cid,proposed['pending_digest']);sync(other)
        contracts[p]=(cid,frozen['contract']['revisions'][-1]['digest'])
        assert any(m['kind']=='contract.frozen' for m in skill(p,'poll')['messages']);sync(p)
    q=skill('a','ask','Verify secure cross-machine collaboration')['message_id'];sync('a')
    incoming=skill('b','poll');assert any(m['message_id']==q for m in incoming['messages']);sync('b')
    skill('b','answer',q,'Secure message received on Tenki B');sync('b');skill('a','poll');sync('a')
    print('NORMAL SECURE MESSAGE PASS; BOTH CONTRACTS FROZEN',flush=True)
    context=json.loads(remote('a','cat '+shlex.quote(P+'/.hacp/session.json'),agent=True).stdout)['session']['session_id']
    binding='sha256:'+contracts['a'][1]
    for p in 'ab':remote(p,shlex.join(['sudo','-u',GU,'test','-r',P+'/.hacp/session.json']))
    start_service()
    sync_log=(STATE/'sync.log').open('w')
    sync_process=subprocess.Popen([str(D/'sync-edge.sh'),'--edge-only'],stdout=sync_log,stderr=sync_log)
    hello=guest('hello.py'); b=hello['body'];assert b['status']=='completed' and b['exit_code']==0 and b['stdout'].strip()=='HACP Wasmer sandbox works',b
    results['hello']=hello;print('LEGITIMATE WASMER EXECUTION PASS (secure request + secure result)',flush=True)
    # The operator checks encrypted transport without printing any envelope internals.
    for p in 'ab':
        code="import pathlib; fs=list(pathlib.Path("+repr(P+'/.hacp-secure')+").rglob('*.json')); assert fs; assert all(b'HACP Wasmer sandbox works' not in f.read_bytes() and b'sandbox.execution' not in f.read_bytes() for f in fs)"
        remote(p,shlex.join(['sudo','python3','-c',code]))
    probe=AH+'/guest-write-probe'
    canary=AH+'/fake-guardian.key'; token='FAKE-GUARDIAN-KEY-'+os.urandom(8).hex()
    put('b',canary,token+'\n');remote('b',shlex.join(['chmod','0600',canary]),agent=True)
    fs=guest('filesystem-denied.py',probe,canary,GH+'/.hacp-secure/identity.json',GH+'/.hacp-secure',GH+'/runtime/b',P+'/.hacp-secure',P+'/.hacp/session.json','/etc/passwd',AH)
    safe_guest(fs);assert token not in json.dumps(fs),'host canary token leaked into sandbox result'
    remote('b','test ! -e '+shlex.quote(probe),agent=True)
    results['filesystem']=fs;print('HOST FILESYSTEM BLOCKED (host-side canary token confirmed absent)',flush=True)
    env=guest('env-denied.py','SANDBOX_GREETING','HACP_GUARDIAN_PRIVATE_KEY','HACP_SESSION_KEY','WASMER_TOKEN',extra=('--env','SANDBOX_GREETING=hello-from-agent-a'))
    safe_guest(env);assert 'GRANTED SANDBOX_GREETING=hello-from-agent-a' in env['body']['stdout'];assert 'FAKE-' not in json.dumps(env)
    results['environment']=env;print('HOST SECRET ENVIRONMENT BLOCKED',flush=True)
    listener="""import socket,pathlib
s=socket.socket();s.bind(('127.0.0.1',0));s.listen();s.settimeout(.2)
p=pathlib.Path('"""+AH+"""');(p/'listener-port').write_text(str(s.getsockname()[1]));(p/'listener-count').write_text('0');n=0
while True:
 try:
  c,_=s.accept();c.close();n+=1;(p/'listener-count').write_text(str(n))
 except socket.timeout: pass
"""
    put('b',AH+'/network-listener.py',listener)
    remote('b',shlex.join(['python3',AH+'/network-listener.py'])+' >/dev/null 2>&1 </dev/null &',agent=True)
    port=remote('b','cat '+shlex.quote(AH+'/listener-port'),agent=True).stdout.strip()
    net=guest('network-denied.py',port);safe_guest(net)
    denied=guest('network-denied.py',port,extra=('--net','ipv4:allow=127.0.0.1:'+port))
    assert denied['body']['status']=='denied' and denied['body']['denial']['code']=='NetworkNotAllowed',denied
    assert remote('b','cat '+shlex.quote(AH+'/listener-count'),agent=True).stdout=='0'
    results['network']=net;results['network_policy']=denied;print('NETWORK BLOCKED: host listener connections=0; out-of-policy grant denied',flush=True)
    timed=client('--package',PACKAGE,'--arg','-c','--arg','while True: pass','--timeout-ms','2000')['returned']
    assert timed['body']['status']=='failed' and timed['body']['failure']['kind']=='TimedOut',timed
    results['timeout']=timed;print('TIMEOUT ENFORCED',flush=True)
    denied=client('--package',PACKAGE,'--arg','-c','--arg','pass','--env','HACP_SESSION_KEY=FAKE-agent-supplied')['returned']
    assert denied['body']['status']=='denied' and denied['body']['denial']['code']=='EnvNotAllowed',denied
    results['denied']=denied;print('UNAPPROVED EXECUTION DENIED BEFORE WASMER',flush=True)
    stop_service();stop_sync();sync()
    # Submit/verify after service relinquishes this session's inbound deliveries.
    put('a',P+'/exec-result.json',hello)
    remote('b','printf verified > '+shlex.quote(P+'/exec-review.txt'),agent=True)
    for p,other,artifact in [('a','b','exec-result.json'),('b','a','exec-review.txt')]:
        value=remote(p,'cat '+shlex.quote(P+'/'+artifact),agent=True).stdout;put(other,P+'/'+artifact,value)
        cid,rev=contracts[p];skill(p,'submit',cid,rev,'--claim','Wasmer secure execution verified');sync(p)
        v=skill(other,'verify',cid);assert v['contract']['state']=='settled',v;sync(other);skill(p,'poll');sync(p)
    print('SECURE /hacp SUBMIT/VERIFY: BOTH CONTRACTS SETTLED',flush=True)
    # Replay is tested on the same running Guardian B after the original delivery.
    audit_before=remote('b','cat '+shlex.quote(AUDIT),agent=True).stdout
    rpc=remote('b',shlex.join(['hacp-secure','recv','--socket',SOCKET['b'],'--hacp-session',context]),agent=True)
    report=json.loads(rpc.stdout);assert not report['delivered'] and any(x['error']=='ReplayRejected' for x in report['rejected']),report
    assert remote('b','cat '+shlex.quote(AUDIT),agent=True).stdout==audit_before
    print('CROSS-VM REPLAY REJECTED: ReplayRejected; no re-execution',flush=True);results['replay']='ReplayRejected'
    sent=client('--package',PACKAGE,'--arg','-c','--arg','print("tamper must never run")','--no-wait')
    # Flip a ciphertext byte on A before relay. Only the operator sees this file.
    mutate="""import pathlib,json
frames=[p for p in pathlib.Path("""+repr(P+'/.hacp-secure')+""").rglob('*-a.json') if 'handshakes' not in p.parts]
p=max(frames,key=lambda f:f.stat().st_mtime_ns);e=json.loads(p.read_text());ct=bytearray.fromhex(e['ct']);ct[0]^=1;e['ct']=ct.hex();p.write_text(json.dumps(e))
"""
    remote('a',shlex.join(['sudo','-u',GU,'python3','-c',mutate]));sync()
    outcomes=start_service(once=True)
    assert any(x['status']=='rejected' and 'BadMessageSignature' in x['detail'] for x in outcomes),outcomes
    audit=remote('b','cat '+shlex.quote(AUDIT),agent=True).stdout
    assert all(x.get('message_id')!=sent['request_id'] for x in map(json.loads,audit.splitlines()))
    print('CROSS-VM TAMPER REJECTED: BadMessageSignature; request never executed',flush=True)
    results['tamper']='BadMessageSignature'
    # The demo contracts already settled; no further polling of the poisoned edge.
    (STATE/'results.json').write_text(json.dumps(results,indent=2))
    (STATE/'exec-audit.jsonl').write_text(audit)
    print('E2E PASS',flush=True)
finally:
    stop_sync()
    for p in list(aliases):
        try:
            if p=='b':stop_service()
            local([D/'guardian.sh',p,'stop'],True)
        except Exception as e: print('service cleanup note: '+str(e),file=sys.stderr)
    # destroy-peer.sh all only terminates IDs recorded by this workflow.
    cleanup=subprocess.run([str(D/'destroy-peer.sh'),'all'])
    # The list API can lag termination briefly; poll instead of a single racy read.
    active=set(resources.values())
    for _ in range(15):
        listing=json.loads(local(['tenki','sandbox','list','--json'],True))
        active={str(x.get('session_id',x.get('sessionId',x.get('id')))) for x in listing}
        if not active.intersection(resources.values()): break
        time.sleep(2)
    assert not active.intersection(resources.values()),'Tenki resources remain listed'
    assert cleanup.returncode==0,'cleanup failed; retained IDs in sessions.json'
    print('CLEANUP PASS: both Tenki environments destroyed',flush=True)
PY
