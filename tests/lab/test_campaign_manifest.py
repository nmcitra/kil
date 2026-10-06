import unittest

from lab.build_campaign_manifest import create, envoy_config
from copy import deepcopy


PUBLIC={name:'cert-sha256:'+format(n,'064x') for n,name in enumerate(
    ('agent-1','agent-2','observer','gateway-client','envoy-client'),1)}


class ManifestSafetyTest(unittest.TestCase):
    def setUp(self):
        self.items=create(PUBLIC,4)['items']
        self.deploy={i['metadata']['name']:i for i in self.items if i['kind']=='Deployment'}
        self.policy={i['metadata']['name'].removeprefix('restrict-'):i for i in self.items if i['kind']=='NetworkPolicy'}

    def test_agent_pods_reach_only_gateway_and_dns(self):
        default=next(x for x in self.items if x['kind']=='NetworkPolicy' and x['metadata']['name']=='default-deny')
        self.assertEqual(default['spec']['podSelector'],{})
        self.assertEqual(default['spec']['policyTypes'],['Ingress','Egress'])
        for agent in ('agent-1','agent-2'):
            p=self.policy[agent]['spec']
            self.assertEqual(p['policyTypes'],['Ingress','Egress'])
            self.assertEqual(p['ingress'],[])
            peers=[t['podSelector']['matchLabels']['app'] for rule in p['egress'] for t in rule['to'] if 'podSelector' in t]
            self.assertEqual(peers,['gateway'])

    def test_private_roles_are_separate_and_no_service_account_mount(self):
        target_args=self.deploy['target']['spec']['template']['spec']['containers'][0]['args']
        values=[target_args[target_args.index(flag)+1] for flag in
            ('-dispatch-principal','-inspector-principal','-observer-principal')]
        self.assertEqual(len(set(values)),3)
        for d in self.deploy.values():
            p=d['spec']['template']['spec']
            self.assertFalse(p['automountServiceAccountToken'])
            for c in p['containers']:
                self.assertEqual(c['imagePullPolicy'],'Never')
                self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
                self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
                self.assertEqual(c['securityContext']['capabilities']['drop'],['ALL'])

    def test_envoy_requires_gateway_identity_and_exact_upstream_names(self):
        cfg=envoy_config()
        listener=cfg['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config']
        self.assertTrue(listener['require_client_certificate'])
        self.assertEqual(listener['common_tls_context']['validation_context']['match_typed_subject_alt_names'][0]['matcher']['exact'],'gateway-client')
        for cluster in cfg['static_resources']['clusters']:
            tls=cluster['transport_socket']['typed_config']
            self.assertEqual(tls['sni'],cluster['name'])
            self.assertEqual(tls['common_tls_context']['validation_context']['match_typed_subject_alt_names'][0]['matcher']['exact'],cluster['name'])
        filters=cfg['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']['http_filters']
        self.assertEqual(filters[0]['name'],'envoy.filters.http.ext_authz')
        self.assertFalse(filters[0]['typed_config']['failure_mode_allow'])

    def test_budget_modes_change_only_gateway_budget(self):
        left=create(PUBLIC,4)
        right=create(PUBLIC,20)
        a=next(x for x in left['items'] if x['kind']=='Deployment' and x['metadata']['name']=='gateway')
        b=next(x for x in right['items'] if x['kind']=='Deployment' and x['metadata']['name']=='gateway')
        av=a['spec']['template']['spec']['containers'][0]['args']
        bv=b['spec']['template']['spec']['containers'][0]['args']
        self.assertEqual(av[av.index('-budget')+1],'4')
        self.assertEqual(bv[bv.index('-budget')+1],'20')

    def test_high_divergence_changes_only_KIL_local_evidence_fixture(self):
        lo=create(PUBLIC,4)
        hi=create(PUBLIC,4,'0.9')
        a=next(x for x in lo['items'] if x['kind']=='Deployment' and x['metadata']['name']=='bridge')
        b=next(x for x in hi['items'] if x['kind']=='Deployment' and x['metadata']['name']=='bridge')
        av=a['spec']['template']['spec']['containers'][0]['args']
        bv=b['spec']['template']['spec']['containers'][0]['args']
        self.assertEqual(av[av.index('--divergence')+1],'0.249')
        self.assertEqual(bv[bv.index('--divergence')+1],'0.9')

    def test_attempt_rate_variant_changes_only_bridge_image_and_mode(self):
        low=create(PUBLIC,20)
        adaptive=create(PUBLIC,20,'0.249','attempt-rate')
        x=next(i for i in low['items'] if i['kind']=='Deployment' and i['metadata']['name']=='bridge')
        y=next(i for i in adaptive['items'] if i['kind']=='Deployment' and i['metadata']['name']=='bridge')
        self.assertNotEqual(x['spec']['template']['spec']['containers'][0]['image'],
                            y['spec']['template']['spec']['containers'][0]['image'])
        args=y['spec']['template']['spec']['containers'][0]['args']
        self.assertEqual(args[args.index('--divergence-mode')+1],'attempt-rate')
        normalized=deepcopy(adaptive)
        bridge=next(i for i in normalized['items'] if i['kind']=='Deployment' and i['metadata']['name']=='bridge')
        bridge['spec']['template']['spec']['containers'][0]['image']=x['spec']['template']['spec']['containers'][0]['image']
        bargs=bridge['spec']['template']['spec']['containers'][0]['args']
        bargs[bargs.index('--divergence-mode')+1]='constant'
        self.assertEqual(normalized,low)

    def test_g15_bridge_reads_gateway_audit_without_write_access(self):
        trial=create(PUBLIC,4,g15=True)
        bridge=next(i for i in trial['items'] if i['kind']=='Deployment' and i['metadata']['name']=='bridge')
        pod=bridge['spec']['template']['spec']
        container=pod['containers'][0]
        self.assertEqual(container['args'][container['args'].index('--earning-audit')+1],
                         '/evidence/gateway.jsonl.audit')
        self.assertTrue(next(m for m in container['volumeMounts'] if m['name']=='gateway-audit')['readOnly'])
        volume=next(v for v in pod['volumes'] if v['name']=='gateway-audit')
        self.assertEqual(volume['persistentVolumeClaim']['claimName'],'gateway-ledger')
        agent=next(i for i in trial['items'] if i['kind']=='Deployment' and i['metadata']['name']=='agent-1')
        self.assertFalse(any(v['name']=='gateway-audit' for v in agent['spec']['template']['spec']['volumes']))


if __name__=='__main__':
    unittest.main()
