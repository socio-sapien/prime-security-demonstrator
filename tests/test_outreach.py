import unittest
from outreach_plan import preflight

class OutreachTests(unittest.TestCase):
    def test_no_send_without_authenticated_review(self):
        r=preflight('send',{'replay_verified':True,'claims_bounded':True,'channel_verified':True,'appropriate_enquiry_channel':True,'draft_complete':True})
        self.assertEqual(r['status'],'BLOCKED')
        self.assertIn('authenticated_owner_send_approval',r['missing_evidence'])
        self.assertEqual(r['external_effects'],0)
    def test_no_sale_without_terms(self):
        r=preflight('contract_or_payment',{})
        self.assertEqual(r['status'],'BLOCKED')
        self.assertIn('voluntary_terms_agreed',r['missing_evidence'])
    def test_simulated_approval_does_not_claim_sent(self):
        r=preflight('send',{x:True for x in ['replay_verified','claims_bounded','channel_verified','appropriate_enquiry_channel','draft_complete','authenticated_owner_send_approval']})
        self.assertEqual(r['status'],'ELIGIBLE_SIMULATION_ONLY')
        self.assertEqual(r['external_effects'],0)

if __name__=='__main__':unittest.main()
