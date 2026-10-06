"""Issue short-lived, synthetic role certificates into one private lab directory.

Operator utility only: output directory is outside source, no key bytes to stdout.
"""
from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROLES = {
    'bridge': (True, False), 'gateway': (True, False),
    'target': (True, False), 'envoy': (True, False),
    'gateway-client': (False, True), 'envoy-client': (False, True),
    'agent-1': (False, True), 'agent-2': (False, True),
    'observer': (False, True),
}


def _write(directory, name, data):
    fd = os.open(directory/name, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW, 0o600)
    try:
        while data:
            n = os.write(fd, data)
            if n <= 0:
                raise OSError('short write')
            data = data[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def create(directory,namespace='ktp-campaign-lab'):
    directory=Path(directory)
    import re
    if re.fullmatch(r'ktp-campaign-[a-z0-9-]{1,35}',namespace) is None:
        raise ValueError('namespace')
    if not directory.is_absolute() or directory.exists():
        raise ValueError('new absolute directory required')
    directory.mkdir(mode=0o700)
    now=datetime.now(timezone.utc)
    ca_key=ec.generate_private_key(ec.SECP256R1())
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'KTP synthetic campaign CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
            key_encipherment=False,data_encipherment=False,key_agreement=False,
            key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
        .sign(ca_key,hashes.SHA256()))
    _write(directory,'ca.pem',ca.public_bytes(serialization.Encoding.PEM))
    _write(directory,'ca-key.pem',ca_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    principals={}
    for role,(server,client) in ROLES.items():
        key=ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,role)])
        dns=[role,role+'.'+namespace+'.svc.cluster.local'] if server else [role]
        usage=[]
        if server: usage.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client: usage.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns]),critical=False)
            .add_extension(x509.ExtendedKeyUsage(usage),critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
                key_encipherment=False,data_encipherment=False,key_agreement=False,
                key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
            .sign(ca_key,hashes.SHA256()))
        _write(directory,role+'.pem',cert.public_bytes(serialization.Encoding.PEM))
        _write(directory,role+'-key.pem',key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        principals[role]='cert-sha256:'+sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    _write(directory,'principals.json',json.dumps(principals,sort_keys=True,separators=(',',':')).encode())
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    os.fsync(fd);os.close(fd)
    return {'roles':sorted(ROLES),'expires_at_utc':(now+timedelta(days=1)).isoformat(),'ca_sha256':sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest()}


if __name__=='__main__':
    p=ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--namespace',default='ktp-campaign-lab')
    args=p.parse_args()
    print(json.dumps(create(args.output,args.namespace),sort_keys=True))
