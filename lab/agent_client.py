"""Fixed-action workload client for the synthetic Kind campaign."""
from argparse import ArgumentParser
import http.client
import json
import re
import ssl

DESTINATIONS={'gateway':'gateway','target':'target','bridge':'bridge','envoy':'envoy'}


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument('--destination',choices=DESTINATIONS,required=True)
    p.add_argument('--operation',choices=('status','marker','witness'),required=True)
    p.add_argument('--marker',choices=('set','clear'),default='set')
    p.add_argument('--expected-version',default='0')
    a=p.parse_args()
    if re.fullmatch(r'0|[1-9][0-9]{0,8}',a.expected_version) is None:
        raise SystemExit('invalid expected version')
    if a.operation=='witness' and a.destination!='target':
        raise SystemExit('invalid witness destination')
    ctx=ssl.create_default_context(cafile='/certs/ca.pem')
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain('/certs/client.pem','/certs/client-key.pem')
    endpoint=DESTINATIONS[a.destination]
    path={'status':'/lab/status','marker':'/lab/marker','witness':'/witness'}[a.operation]
    method='POST' if a.operation=='marker' else 'GET'
    body=None
    headers={}
    if a.operation=='marker':
        body=json.dumps({'marker':a.marker,'expected_version':a.expected_version},separators=(',',':')).encode()
        headers['Content-Type']='application/json'
    conn=http.client.HTTPSConnection(endpoint,8443,context=ctx,timeout=5)
    try:
        conn.request(method,path,body=body,headers=headers)
        response=conn.getresponse()
        raw=response.read(32769)
        if len(raw)>32768:
            raise ValueError('response_limit')
        try:
            value=json.loads(raw)
        except (ValueError,UnicodeDecodeError):
            value={'non_json_response':True}
        print(json.dumps({'http_status':response.status,'response':value},sort_keys=True,separators=(',',':')))
    except (OSError,ssl.SSLError,TimeoutError) as exc:
        print(json.dumps({'network_error':type(exc).__name__},sort_keys=True))
    finally:
        conn.close()


if __name__=='__main__':
    main()
