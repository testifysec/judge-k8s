
  
#!/usr/bin/env bash

# Copyright (c) 2019 StackRox Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# generate-keys.sh
#
# Generate a (self-signed) CA certificate and a certificate and private key to be used by the webhook demo server.
# The certificate will be issued for the Common Name (CN) of `judge-k8s-webhook.default.svc`, which is the
# cluster-internal DNS name for the service.
#
# NOTE: THIS SCRIPT EXISTS FOR DEMO PURPOSES ONLY. DO NOT USE IT FOR YOUR PRODUCTION WORKLOADS.

cat >server.conf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = judge-k8s-webhook.default.svc
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = judge-k8s-webhook.default.svc
EOF


# Generate the CA cert and private key
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=Admission Controller Webhook Demo CA"
# Generate the private key for the webhook server
openssl genrsa -out webhook-server-tls.key 2048
# Generate a Certificate Signing Request (CSR) for the private key, and sign it with the private key of the CA.
openssl req -new -key webhook-server-tls.key -subj "/CN=judge-k8s-webhook.default.svc" -config server.conf \
    | openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -out webhook-server-tls.crt -extensions v3_req -extfile server.conf

cd k8s

kubectl create secret tls webhook-server-tls \
    --cert "../webhook-server-tls.crt" \
    --key "../webhook-server-tls.key" \
    --dry-run=client -o yaml > webhook-server-tls.yaml

cd ..

ca_pem_b64="$(openssl base64 -A <"ca.crt")"
sed -e 's@${CA_PEM_B64}@'"$ca_pem_b64"'@g' <"deploy.tmpl.yml" > "k8s/judge-k8s-webhook.yaml"
