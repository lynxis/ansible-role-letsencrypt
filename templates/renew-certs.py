#!/usr/bin/env python3

import os
import time
import re
from datetime import datetime

import subprocess

def get_expires(certpath):
    proc = subprocess.Popen(["openssl", "x509", "-in", certpath, "-noout", "-text"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out = proc.communicate()[0]
    if proc.returncode != 0:
        raise IOError("OpenSSL Error.")
    expires = re.search(
            r"Not After : (.*)",
            out.decode('utf8')).groups()[0]
    return datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')

certs = {{letsencrypt_certs}}
script = "{{ acme_tiny_software_directory }}/acme_tiny.py"

for cert in certs:
    if os.access(cert['certpath'], os.F_OK):
        print("Certificate file " + cert['certpath'] + " already exists")

        if (get_expires(cert['certpath']).timestamp() - time.time()) > {{ letsencrypt_min_valid_days }} * 86400:
            print("  The certificate is still valid for longer than {{ letsencrypt_min_valid_days }} days. Not creating a new certificate.\n")
            continue

    host = ",".join(cert['host']) if type(cert['host']) is list else cert['host']

    print("Generating certificate for " + host)
    args = [
        "/usr/bin/env", "python", script,

        "--account-key",
        "{{ letsencrypt_account_key }}",
        "--csr",
        "{{ acme_tiny_data_directory }}/csrs/" + cert['name'] + ".csr",
        "--acme-dir",
        "{{ acme_tiny_challenges_directory }}"
    ]

    cmd = "/usr/bin/env " + " ".join(args)

    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    output = p.stdout.read()
    p.stdin.close()
    if p.wait() != 0:
        print("error while generating certificate for " + host)
        print(p.stderr.read())
    else:
        f = open(cert['certpath'], 'wb')
        f.write(output)
        f.close()
        if 'chainedcertpath' in cert:
          intermediate_cert = open('{{letsencrypt_intermediate_cert_path}}', 'rb')
          f = open(cert['chainedcertpath'], 'wb')
          f.write(output)
          f.write(intermediate_cert.read())
          f.close()
        if 'fullchainedcertpath' in cert:
          intermediate_cert = open('{{letsencrypt_intermediate_cert_path}}', 'rb')
          private_key = open(cert['keypath'], 'rb')
          f = open(cert['fullchainedcertpath'], 'wb')
          f.write(private_key.read())
          f.write(output)
          f.write(intermediate_cert.read())
          f.close()
