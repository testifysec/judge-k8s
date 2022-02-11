
#!/usr/bin/env bash

set -e
set -x



# cat >server.conf <<EOF
# [req]
# req_extensions = v3_req
# distinguished_name = req_distinguished_name
# prompt = no
# [req_distinguished_name]
# CN = judge-k8s-webhook.judge-test.svc
# [ v3_req ]
# basicConstraints = CA:FALSE
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment
# extendedKeyUsage = clientAuth, serverAuth
# subjectAltName = @alt_names
# [alt_names]
# DNS.1 = judge-k8s-webhook.judge-test.svc
# EOF


# # Generate the CA cert and private key
# openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=Admission Controller Webhook Demo CA"
# # Generate the private key for the webhook server
# openssl genrsa -out webhook-server-tls.key 2048
# # Generate a Certificate Signing Request (CSR) for the private key, and sign it with the private key of the CA.
# openssl req -new -key webhook-server-tls.key -subj "/CN=judge-k8s-webhook.judge-test.svc" -config server.conf \
#     | openssl x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -out webhook-server-tls.crt -extensions v3_req -extfile server.conf

# cd k8s

# kubectl create secret -n=judge-test tls webhook-server-tls \
#     --cert "../webhook-server-tls.crt" \
#     --key "../webhook-server-tls.key" \
#     --dry-run=client -o yaml > webhook-server-tls.yaml

# cd ..

openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem

#inject rego

#get b64 of policy
rego_b64="$(openssl base64 -A <"testpolicy.rego")"

#add b64 rego to policy template
cp policy-template.json policy.tmp.json

id=`sha256sum testpub.pem | awk '{print $1}'` && sed -i "s/{{PUBLIC_KEY_ID}}/$id/g" policy.tmp.json
pubb64=`cat testpub.pem | base64 -w 0` && sed -i "s/{{B64_PUBLIC_KEY}}/$pubb64/g" policy.tmp.json
sed -i "s/{{B64_POLICY_MODULE}}/$rego_b64/g" policy.tmp.json

#sign policy with witness
witness -c witness-conf.yaml sign -f policy.tmp.json
#rm policy.tmp.json

policy=`cat policy-signed.json`

# webhook server TLS
ca_pem_b64="$(openssl base64 -A <"ca.crt")"


# witnesspolicy public key to trust (this goes into the webhook config)
pubb64=`cat testpub.pem | base64 -w 0`


cp deploy.tmpl.yaml judge-k8s-webhook.yaml

#add the CA to the webhook config
sed -i "s/{{CA_PEM_B64}}/$ca_pem_b64/g" judge-k8s-webhook.yaml
# sed -e 's@${CA_PEM_B64}@'"$ca_pem_b64"'@g' <"deploy.tmpl.yml" > "deploy.tmpl.tmp.yml"

# add the signed witness policy to the wbhookconfig
sed -i "s#{{WITNESSPOLICY}}#$policy#g" judge-k8s-webhook.yaml
# sed -e 's@${WITNESSPOLICY}@'"$policy"'@g' <"deploy.tmpl.tmp.yml" > "deploy.tmpl.tmp1.yml"

# add the witness policy public key to the webhook config
sed -i "s/{{PUBLIC_KEY_B64}}/$pubb64/g" judge-k8s-webhook.yaml

mv judge-k8s-webhook.yaml ./k8s/judge-k8s-webhook.yaml

# sed -e 's@${PUBKEYPEM}@'"`echo $pub`"'@g' <"deploy.tmpl.tmp1.yml" > "k8s/judge-k8s-webhook.yaml"

./gen-attestation.sh

rm policy-signed.json

