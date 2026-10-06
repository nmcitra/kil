"""Render a closed synthetic KIL/KAG Kind campaign manifest without secrets."""
from argparse import ArgumentParser
import json
from pathlib import Path

NS='ktp-campaign-lab'
KAG_IMAGE='kag-campaign-lab:20261002'
BRIDGE_IMAGE='kil-campaign-bridge:20261002'
BRIDGE_ADAPTIVE_IMAGE='kil-campaign-bridge:adaptive-bound-20261002'
BRIDGE_G15_IMAGE='kil-campaign-bridge:g15-20261005'
AGENT_IMAGE='kil-campaign-agent:20261002'
KIL_IMAGE='kil-aware:20261002'
# Kind imports the verified native manifest under a local tag. Its containerd
# target digest is verified against the upstream pin before deployment.
ENVOY_IMAGE='envoy-campaign-native:20261002'


def service(name):
    return {'apiVersion':'v1','kind':'Service','metadata':{'name':name,'namespace':NS},
        'spec':{'selector':{'app':name},'ports':[{'port':8443,'targetPort':8443,'name':'https'}]}}


def pvc(name):
    return {'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':name,'namespace':NS},
        'spec':{'accessModes':['ReadWriteOnce'],'storageClassName':'standard',
            'resources':{'requests':{'storage':'1Gi'}}}}


def deployment(name,image,args,secret,*,pvc_name=None,config=False,g15_audit=False):
    mounts=[{'name':'identity','mountPath':'/certs','readOnly':True}]
    volumes=[{'name':'identity','secret':{'secretName':secret,'defaultMode':288}}]
    if pvc_name:
        mounts.append({'name':'journal','mountPath':'/journal'})
        volumes.append({'name':'journal','persistentVolumeClaim':{'claimName':pvc_name}})
    if config:
        mounts.append({'name':'config','mountPath':'/etc/envoy','readOnly':True})
        volumes.append({'name':'config','configMap':{'name':'envoy-config'}})
        mounts.append({'name':'tmp','mountPath':'/tmp'})
        volumes.append({'name':'tmp','emptyDir':{}})
    if name=='gateway':
        mounts.append({'name':'principals','mountPath':'/config','readOnly':True})
        volumes.append({'name':'principals','configMap':{'name':'gateway-principals'}})
    if g15_audit:
        if name != 'bridge':
            raise ValueError('g15 audit mount only belongs to bridge')
        mounts.append({'name':'gateway-audit','mountPath':'/evidence','readOnly':True})
        volumes.append({'name':'gateway-audit','persistentVolumeClaim':{
            'claimName':'gateway-ledger','readOnly':True}})
    container={'name':name,'image':image,'imagePullPolicy':'Never','args':args,
        'ports':[{'containerPort':8443,'name':'https'}],
        'volumeMounts':mounts,
        'resources':{'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'1','memory':'512Mi'}},
        'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,
            'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,
            'capabilities':{'drop':['ALL']},'seccompProfile':{'type':'RuntimeDefault'}}}
    if name=='gateway':
        collector={'name':'collector','image':KIL_IMAGE,'imagePullPolicy':'Never',
            'command':['python','-c','import time; time.sleep(3600)'],
            'volumeMounts':[{'name':'journal','mountPath':'/journal','readOnly':True}],
            'resources':{'requests':{'cpu':'25m','memory':'32Mi'},'limits':{'cpu':'100m','memory':'128Mi'}},
            'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,
                'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,
                'capabilities':{'drop':['ALL']},'seccompProfile':{'type':'RuntimeDefault'}}}
        containers=[container,collector]
    else:
        containers=[container]
    return {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':name,'namespace':NS},
        'spec':{'replicas':1,'strategy':{'type':'Recreate'},'selector':{'matchLabels':{'app':name}},
            'template':{'metadata':{'labels':{'app':name}},'spec':{
                'automountServiceAccountToken':False,'securityContext':{'fsGroup':65532},
                'containers':containers,'volumes':volumes}}}}


def dns_rule():
    return {'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'kube-system'}}}],
        'ports':[{'protocol':'UDP','port':53},{'protocol':'TCP','port':53}]}


def policy(name,ingress_from,egress_to):
    ing=[] if not ingress_from else [{'from':[{'podSelector':{'matchLabels':{'app':x}}} for x in ingress_from],
        'ports':[{'protocol':'TCP','port':8443}]}]
    eg=[dns_rule()]
    for x in egress_to:
        eg.append({'to':[{'podSelector':{'matchLabels':{'app':x}}}],
            'ports':[{'protocol':'TCP','port':8443}]})
    return {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
        'metadata':{'name':'restrict-'+name,'namespace':NS},
        'spec':{'podSelector':{'matchLabels':{'app':name}},
            'policyTypes':['Ingress','Egress'],'ingress':ing,'egress':eg}}


def envoy_config():
    match=lambda n:{'patterns':[{'exact':n}]}
    dirs=[{'exact':'x-kag-'+x.replace('_','-')} for x in ('binding_digest','operation_digest','replay_id','actor_id','tenant_id','operation_id')]
    allowed={'patterns':dirs}
    ext={'@type':'type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz',
        'failure_mode_allow':False,'status_on_error':{'code':'ServiceUnavailable'},
        'http_service':{'server_uri':{'uri':'https://bridge:8443','cluster':'bridge','timeout':'2s'},
            'authorization_request':{'allowed_headers':allowed},
            'authorization_response':{'allowed_upstream_headers':match('x-kil-decision-digest')}}}
    hcm={'@type':'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
        'stat_prefix':'campaign','route_config':{'name':'target','virtual_hosts':[{'name':'target',
        'domains':['*'],'request_headers_to_remove':[
            'forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto',
            'x-envoy-internal','x-envoy-expected-rq-timeout-ms'],
        'routes':[{'match':{'prefix':'/'},'route':{'cluster':'target','host_rewrite_literal':'target:8443'}}]}]},
        'access_log':[{'name':'envoy.access_loggers.stdout','typed_config':{
            '@type':'type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog',
            'log_format':{'text_format_source':{'inline_string':
                '{"replay_id":"%REQ(X-KAG-REPLAY-ID)%","code":"%RESPONSE_CODE%","detail":"%RESPONSE_CODE_DETAILS%","upstream":"%UPSTREAM_HOST%"}\n'}}}}],
        'http_filters':[{'name':'envoy.filters.http.ext_authz','typed_config':ext},
                        {'name':'envoy.filters.http.router','typed_config':{'@type':'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router'}}]}
    def context(role):
        return {'tls_params':{'tls_minimum_protocol_version':'TLSv1_3','tls_maximum_protocol_version':'TLSv1_3'},
          'tls_certificates':[{'certificate_chain':{'filename':'/certs/'+role+'.pem'},
                               'private_key':{'filename':'/certs/'+role+'-key.pem'}}],
          'validation_context':{'trusted_ca':{'filename':'/certs/ca.pem'}}}
    def cluster(name):
        tls=context('envoy-client')
        tls['validation_context']['match_typed_subject_alt_names']=[{'san_type':'DNS','matcher':{'exact':name}}]
        c={'name':name,'type':'STRICT_DNS','connect_timeout':'2s','lb_policy':'ROUND_ROBIN',
            'load_assignment':{'cluster_name':name,'endpoints':[{'lb_endpoints':[
                {'endpoint':{'address':{'socket_address':{'address':name,'port_value':8443}}}}]}]},
            'transport_socket':{'name':'envoy.transport_sockets.tls',
                'typed_config':{'@type':'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext',
                    'sni':name,'common_tls_context':tls}}}
        return c
    down=context('envoy')
    down['validation_context']['match_typed_subject_alt_names']=[{'san_type':'DNS','matcher':{'exact':'gateway-client'}}]
    return {'static_resources':{'listeners':[{'name':'inbound','address':{'socket_address':{'address':'0.0.0.0','port_value':8443}},
        'filter_chains':[{'filters':[{'name':'envoy.filters.network.http_connection_manager','typed_config':hcm}],
            'transport_socket':{'name':'envoy.transport_sockets.tls',
                'typed_config':{'@type':'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
                    'require_client_certificate':True,'common_tls_context':down}}}]}],
        'clusters':[cluster('bridge'),cluster('target')]},
        'admin':{'address':{'pipe':{'path':'/tmp/envoy-admin.sock'}}}}


def create(principals,budget,divergence='0.249',divergence_mode='constant',g15=False):
    if budget not in (4,20):
        raise ValueError('budget')
    if divergence not in ('0.249','0.9'):
        raise ValueError('closed divergence fixture')
    if divergence_mode not in ('constant','attempt-rate') or (divergence_mode=='attempt-rate' and divergence!='0.249'):
        raise ValueError('closed divergence mode')
    role=lambda name:principals[name]
    items=[{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
        'metadata':{'name':'default-deny','namespace':NS},
        'spec':{'podSelector':{},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[]}}]
    items.extend([pvc('gateway-ledger'),pvc('target-ledger')])
    items.append({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'envoy-config','namespace':NS},
        'data':{'envoy.json':json.dumps(envoy_config(),sort_keys=True,separators=(',',':'))}})
    items.append({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'gateway-principals','namespace':NS},
        'data':{'principals.json':json.dumps({role(x):x for x in ('agent-1','agent-2')},sort_keys=True)}})
    items.extend([
        deployment('bridge',BRIDGE_G15_IMAGE if g15 else BRIDGE_ADAPTIVE_IMAGE if divergence_mode=='attempt-rate' else BRIDGE_IMAGE,['--listen-port','8443','--server-cert','/certs/bridge.pem',
            '--server-key','/certs/bridge-key.pem','--client-ca','/certs/ca.pem',
            '--allowed-client-cert','/certs/gateway-client.pem','--allowed-client-cert','/certs/envoy-client.pem',
            '--ledger','/journal/decisions.jsonl','--divergence',divergence,
            '--divergence-mode',divergence_mode]+(['--earning-audit','/evidence/gateway.jsonl.audit'] if g15 else []),
            'bridge-identity',pvc_name='bridge-ledger',g15_audit=g15),
        deployment('target',KAG_IMAGE,['-mode','target','-listen',':8443','-authority','target:8443',
            '-server-cert','/certs/target.pem','-server-key','/certs/target-key.pem',
            '-client-ca','/certs/ca.pem','-journal','/journal/target.jsonl',
            '-dispatch-principal',role('envoy-client'),'-inspector-principal',role('gateway-client'),
            '-observer-principal',role('observer')],'target-identity',pvc_name='target-ledger'),
        deployment('gateway',KAG_IMAGE,['-mode','gateway','-listen',':8443','-authority','gateway:8443',
            '-server-cert','/certs/gateway.pem','-server-key','/certs/gateway-key.pem',
            '-client-ca','/certs/ca.pem','-journal','/journal/gateway.jsonl',
            '-budget',str(budget),'-spacing','1m','-principals','/config/principals.json',
            '-inspect-url','https://target:8443','-decision-url','https://bridge:8443/decision',
            '-target-url','https://envoy:8443','-client-cert','/certs/gateway-client.pem',
            '-client-key','/certs/gateway-client-key.pem','-upstream-ca','/certs/ca.pem'],
            'gateway-identity',pvc_name='gateway-ledger'),
        deployment('envoy',ENVOY_IMAGE,['-c','/etc/envoy/envoy.json','--log-level','warning'],
            'envoy-identity',config=True),
        deployment('agent-1',AGENT_IMAGE,[],'agent-1-identity'),
        deployment('agent-2',AGENT_IMAGE,[],'agent-2-identity'),
        deployment('observer',AGENT_IMAGE,[],'observer-identity')])
    items.append(pvc('bridge-ledger'))
    items.append(service('bridge'));items.append(service('target'));items.append(service('gateway'));items.append(service('envoy'))
    items.extend([policy('gateway',['agent-1','agent-2'],['bridge','target','envoy']),
        policy('target',['gateway','envoy','observer'],[]),
        policy('bridge',['gateway','envoy'],[]),
        policy('envoy',['gateway'],['bridge','target']),
        policy('agent-1',[],['gateway']),policy('agent-2',[],['gateway']),
        policy('observer',[],['target'])])
    return {'apiVersion':'v1','kind':'List','items':items}


if __name__=='__main__':
    p=ArgumentParser(description=__doc__)
    p.add_argument('--namespace',default=NS)
    p.add_argument('--public-principals',type=Path,required=True)
    p.add_argument('--budget',type=int,required=True)
    p.add_argument('--divergence',default='0.249')
    p.add_argument('--divergence-mode',default='constant')
    p.add_argument('--g15',action='store_true')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    import re
    if re.fullmatch(r'ktp-campaign-[a-z0-9-]{1,35}',a.namespace) is None:
        raise SystemExit('invalid campaign namespace')
    NS=a.namespace
    public=json.loads(a.public_principals.read_text())
    a.output.write_text(json.dumps(create(public,a.budget,a.divergence,a.divergence_mode,a.g15),indent=2)+'\n')
