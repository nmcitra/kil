"""Create an owned synthetic campaign namespace with policies before workloads."""
from argparse import ArgumentParser
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess

CLI='/Users/mistorm/Documents/AI-Projects/Kinetic Infrastructure Layer - KIL/.tools/bin/kubectl'


def run(argv, *, stdin=None, timeout=90):
    p=subprocess.run(argv,input=stdin,capture_output=True,text=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError('kubectl operation failed: '+p.stderr[:180])
    return p.stdout


def append(journal, phase, extra=None):
    row={'phase':phase}
    if extra:row.update(extra)
    with journal.open('a') as f:
        f.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n')
        f.flush();os.fsync(f.fileno())


def deploy(namespace,manifest,identity,kubeconfig,runroot):
    if re.fullmatch(r'ktp-campaign-[a-z0-9-]{1,35}',namespace) is None:
        raise ValueError('namespace')
    manifest=Path(manifest);identity=Path(identity);kubeconfig=Path(kubeconfig)
    data=json.loads(manifest.read_text())
    if data['kind']!='List' or not all(x['metadata']['namespace']==namespace for x in data['items']):
        raise ValueError('manifest namespace')
    base=[CLI,'--kubeconfig',str(kubeconfig)]
    existing=run(base+['get','namespace',namespace,'--ignore-not-found','-o','name']).strip()
    if existing:
        raise ValueError('namespace already exists; no adoption authority')
    runroot=Path(runroot)
    runroot.mkdir(mode=0o700)
    journal=runroot/'journal.jsonl'
    fd=os.open(journal,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    os.fsync(fd);os.close(fd)
    fd=os.open(runroot,os.O_RDONLY|os.O_DIRECTORY)
    os.fsync(fd);os.close(fd)
    append(journal,'prepared',{'namespace':namespace,'manifest_sha256':sha256(manifest.read_bytes()).hexdigest(),
        'kube_system_uid':run(base+['get','namespace','kube-system','-o','jsonpath={.metadata.uid}']).strip()})
    names={x['metadata']['name'] for x in data['items'] if x['kind']=='NetworkPolicy'}
    if 'default-deny' not in names or len(names)<8:
        raise ValueError('default deny/policies missing')
    append(journal,'namespace_create_intent')
    run(base+['create','namespace',namespace])
    append(journal,'namespace_created')
    rules={'apiVersion':'v1','kind':'List','items':[x for x in data['items'] if x['kind']=='NetworkPolicy']}
    append(journal,'policies_apply_intent')
    run(base+['apply','-f','-'],stdin=json.dumps(rules))
    append(journal,'policies_applied',{'count':len(rules['items'])})
    role_files={
     'bridge-identity':{'ca.pem':'ca.pem','bridge.pem':'bridge.pem','bridge-key.pem':'bridge-key.pem','gateway-client.pem':'gateway-client.pem','envoy-client.pem':'envoy-client.pem'},
     'gateway-identity':{'ca.pem':'ca.pem','gateway.pem':'gateway.pem','gateway-key.pem':'gateway-key.pem','gateway-client.pem':'gateway-client.pem','gateway-client-key.pem':'gateway-client-key.pem'},
     'target-identity':{'ca.pem':'ca.pem','target.pem':'target.pem','target-key.pem':'target-key.pem'},
     'envoy-identity':{'ca.pem':'ca.pem','envoy.pem':'envoy.pem','envoy-key.pem':'envoy-key.pem','envoy-client.pem':'envoy-client.pem','envoy-client-key.pem':'envoy-client-key.pem'},
    }
    for role in ('agent-1','agent-2','observer'):
        role_files[role+'-identity']={'ca.pem':'ca.pem','client.pem':role+'.pem','client-key.pem':role+'-key.pem'}
    for name, mapping in role_files.items():
        append(journal,'role_secret_create_intent',{'name':name})
        args=base+['-n',namespace,'create','secret','generic',name]
        args+=['--from-file='+k+'='+str(identity/v) for k,v in mapping.items()]
        run(args,timeout=35)
        append(journal,'role_secret_created',{'name':name})
    run(base+['apply','--dry-run=server','-f',str(manifest)])
    append(journal,'workload_apply_intent')
    run(base+['apply','-f',str(manifest)])
    append(journal,'workload_applied')
    return len(data['items'])


if __name__=='__main__':
    p=ArgumentParser(description=__doc__)
    for arg in ('namespace','manifest','identity','kubeconfig','runroot'):
        p.add_argument('--'+arg,required=True)
    a=p.parse_args()
    print(json.dumps({'namespace':a.namespace,'resources':deploy(a.namespace,a.manifest,a.identity,a.kubeconfig,a.runroot)}))
