#!/usr/bin/env python3
"""Offline engagement preflight. No send, scheduling, form, credential or payment adapter."""
import hashlib, json, pathlib
import security_demo as demo
ROOT=pathlib.Path(__file__).resolve().parent

def preflight(stage, facts):
    required={
        'owner_review':['replay_verified','claims_bounded','channel_verified','appropriate_enquiry_channel','draft_complete'],
        'send':['replay_verified','claims_bounded','channel_verified','appropriate_enquiry_channel','draft_complete','authenticated_owner_send_approval'],
        'evaluation':['confirmed_interest','problem_owner_named','sample_authorization','scope_agreed','baseline_agreed'],
        'commercial_proposal':['confirmed_interest','results_reviewed','budget_owner_named','scope_agreed'],
        'contract_or_payment':['voluntary_terms_agreed','authenticated_commitment_approval'],
    }
    if stage not in required:raise ValueError('Unknown stage')
    missing=[key for key in required[stage] if facts.get(key) is not True]
    return {'stage':stage,'status':'BLOCKED' if missing else 'READY_FOR_OWNER_REVIEW' if stage=='owner_review' else 'ELIGIBLE_SIMULATION_ONLY',
            'missing_evidence':missing,'external_effects':0,
            'limit':'Boolean fixtures simulate evidence; they cannot authenticate approval or establish an external outcome.'}

def main():
    cases,results=demo.suite()
    current={'replay_verified':all(r['actual_allowed']==r['expected_allowed'] and demo.verify_report(r) for r in results),
             'claims_bounded':True,'channel_verified':True,'appropriate_enquiry_channel':True,'draft_complete':True}
    # These are scenario inputs, not a replacement for the actual external review workflow.
    output={'mode':'OFFLINE DRY RUN; NOTHING SENT',
            'repository':'https://github.com/socio-sapien/prime-security-demonstrator',
            'review_package':preflight('owner_review',current),
            'unapproved_send':preflight('send',current),
            'unearned_close':preflight('contract_or_payment',current),
            'evaluation_without_reply':preflight('evaluation',current)}
    output['integrity_sha256']=demo.digest(output)
    print(json.dumps(output,indent=2))
if __name__=='__main__':main()
