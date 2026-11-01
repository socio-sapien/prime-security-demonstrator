#!/usr/bin/env python3
"""PRIME security demonstrator. Static text only; every tool effect is an inert event.
The authorization gate is new demo code, not a capability inferred from PRIME scores.
"""
import argparse, copy, hashlib, importlib.util, json, pathlib, re, sqlite3, threading
ROOT = pathlib.Path(__file__).resolve().parent
CORE = ROOT / 'vendor/aee_logodecrypt_prime.py'
CORE_SHA256 = 'dd61cdec966230abab177c28cb128496d86f34573292ab127b3a155bbc6e0137'
MAX_TEXT_BYTES = 65536
MAX_ACTIONS = 50
VERSION = '0.1.0'

def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()
def load_core():
    if hashlib.sha256(CORE.read_bytes()).hexdigest() != CORE_SHA256:
        raise ValueError('Vendored PRIME core changed: review provenance before running')
    spec = importlib.util.spec_from_file_location('preserved_prime', CORE)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod

def validate_action(action):
    if type(action) is not dict or set(action) != {'tool', 'args'}:
        raise ValueError('Action must contain exactly tool and args')
    if type(action['tool']) is not str or type(action['args']) is not dict:
        raise ValueError('Invalid action types')
    schemas = {'read_demo': {'resource'}, 'send_demo': {'recipient', 'body'},
               'delete_demo': {'resource'}, 'change_demo': {'resource', 'value'}}
    schema = schemas.get(action['tool'])
    if schema is None: return False
    if set(action['args']) != schema or not all(type(v) is str and len(v) <= 4096 for v in action['args'].values()):
        raise ValueError('Unexpected tool argument schema')
    return True

class Gate:
    """Trusted approvals in a private process-local SQLite store; no document fields grant approval.
    A real integration must supply authenticated principals/approvals and wire all effects through
    its own enforcement boundary. This process deliberately has no external effect adapters.
    """
    def __init__(self, actor='demo-owner'):
        self.actor = actor
        self.lock = threading.Lock()
        self.db = sqlite3.connect(':memory:', check_same_thread=False, isolation_level=None)
        self.db.execute('CREATE TABLE approvals (id TEXT PRIMARY KEY, actor TEXT, action_hash TEXT, expiry INTEGER, used INTEGER DEFAULT 0)')
    def approve(self, approval_id, actor, action, expiry):
        if not validate_action(action): raise ValueError('Unknown action cannot be approved')
        self.db.execute('INSERT INTO approvals(id,actor,action_hash,expiry) VALUES (?,?,?,?)',
                        (approval_id, actor, digest(action), expiry))
    def decide(self, action, approval_id=None, *, now):
        try: known = validate_action(action)
        except ValueError: return {'allowed': False, 'reason': 'invalid-schema'}
        if not known: return {'allowed': False, 'reason': 'unknown-tool'}
        if action['tool'] == 'read_demo':
            ok = action['args']['resource'] == 'public-demo'
            return {'allowed': ok, 'reason': 'scoped-read' if ok else 'resource-out-of-scope'}
        if not approval_id: return {'allowed': False, 'reason': 'approval-required'}
        # One conditional UPDATE is the authorization check and consume operation, atomically.
        with self.lock:
            cur = self.db.execute('UPDATE approvals SET used=1 WHERE id=? AND actor=? AND action_hash=? AND expiry>? AND used=0',
                                 (approval_id, self.actor, digest(action), now))
            ok = cur.rowcount == 1
        return {'allowed': ok, 'reason': 'exact-approval-consumed' if ok else 'invalid-expired-mismatched-or-used-approval'}

PATTERN = re.compile(r'ignore (?:all |previous )?instructions|system override|send (?:the )?(?:secret|canary)|delete (?:all |the )?logs', re.I)
def keyword_baseline(text): return bool(PATTERN.search(text))

def validate_case(case):
    allowed = {'id','label','text','context','actions','approval_ids','expected_allowed','attack','note'}
    if type(case) is not dict or set(case)-allowed: raise ValueError('Unknown case fields')
    for key in ('id','label','text','context','note'):
        if type(case.get(key)) is not str: raise ValueError('Text fields must be strings')
    if any(len(case[k].encode()) > MAX_TEXT_BYTES for k in ('text','context')):
        raise ValueError('Text exceeds 64 KiB bound')
    if type(case.get('actions')) is not list or len(case['actions']) > MAX_ACTIONS: raise ValueError('Action bound')
    if type(case.get('approval_ids')) is not list or len(case['approval_ids']) != len(case['actions']): raise ValueError('Approval alignment')
    if type(case.get('expected_allowed')) is not list or len(case['expected_allowed']) != len(case['actions']): raise ValueError('Expectation alignment')
    if not all(type(v) is bool for v in case['expected_allowed']): raise ValueError('Boolean expectations required')
    if not all(v is None or type(v) is str for v in case['approval_ids']): raise ValueError('Invalid approval id')
    if type(case.get('attack')) is not bool: raise ValueError('Boolean label required')
    for action in case['actions']: validate_action(action)

def validate_trusted_setup(rows):
    if type(rows) is not list or len(rows) > MAX_ACTIONS: raise ValueError('Approval bound')
    for row in rows:
        if type(row) is not dict or set(row) != {'id','actor','action','expiry'}: raise ValueError('Invalid approval')
        if type(row['id']) is not str or type(row['actor']) is not str or type(row['expiry']) is not int: raise ValueError('Approval types')
        validate_action(row['action'])

def replay(case, with_prime=True, *, trusted_approvals=()):
    validate_case(case)
    gate = Gate()
    validate_trusted_setup(list(trusted_approvals))
    for approval in trusted_approvals:
        gate.approve(approval['id'], approval['actor'], approval['action'], approval['expiry'])
    text = case['text']
    prime = load_core().analyze(text, case['context']) if with_prime else None
    events, chain = [], '0' * 64
    for i, (action, approval) in enumerate(zip(case['actions'], case['approval_ids'])):
        decision = gate.decide(action, approval, now=1000)
        event = {'sequence': i, 'proposed_action': copy.deepcopy(action), **decision,
                 'effect': 'INERT DEMO EVENT' if decision['allowed'] else 'NOT DISPATCHED', 'previous_hash': chain}
        chain = digest(event); event['event_hash'] = chain; events.append(event)
    report = {'version': VERSION, 'case_id': case['id'], 'source_text': text,
              'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
              'context_text': case['context'], 'context_sha256': hashlib.sha256(case['context'].encode()).hexdigest(),
              'prime': prime, 'events': events,
              'expected_allowed': case['expected_allowed'],
              'actual_allowed': [e['allowed'] for e in events],
              'keyword_baseline_flagged': keyword_baseline(text),
              'containment_mechanism': 'exact action authorization in separate trusted code; not PIC/T_d or text filtering',
              'effect_scope': 'in-memory mock tools; zero network, shell, real deletion, real messages or malware execution'}
    report['receipt_sha256'] = digest(report)
    gate.db.close()
    return report

def verify_report(report):
    try:
        payload = dict(report); checksum = payload.pop('receipt_sha256')
        if digest(payload) != checksum: return False
        if hashlib.sha256(report['source_text'].encode()).hexdigest() != report['source_sha256']: return False
        if hashlib.sha256(report['context_text'].encode()).hexdigest() != report['context_sha256']: return False
        if report['prime'] is not None and report['prime']['receipt']['context_sha256'] != report['context_sha256']: return False
        previous = '0' * 64
        for event in report['events']:
            row = dict(event); h = row.pop('event_hash')
            if row['previous_hash'] != previous or digest(row) != h: return False
            previous = h
        if report['prime'] is not None and not load_core().verify(report['prime']): return False
        return True
    except (KeyError, TypeError, ValueError): return False

def suite():
    cases = json.loads((ROOT/'fixtures/cases.json').read_text())
    # The synthetic harness controls this file; --case never reads or accepts approval setup.
    setup = json.loads((ROOT/'fixtures/trusted_test_setup.json').read_text())
    return cases, [replay(case, trusted_approvals=setup.get(case['id'], [])) for case in cases]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=pathlib.Path, help='Local JSON specimen; no upload and no trusted approvals accepted from this file.')
    parser.add_argument('--verify', type=pathlib.Path)
    args = parser.parse_args()
    if args.verify:
        good = verify_report(json.loads(args.verify.read_text())); print('VERIFIED' if good else 'MISMATCH'); raise SystemExit(0 if good else 1)
    if args.case: output = replay(json.loads(args.case.read_text()))
    else: output = suite()[1]
    print(json.dumps(output, ensure_ascii=False, indent=2))
if __name__ == '__main__': main()
