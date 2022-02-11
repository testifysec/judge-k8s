#/bin/bash

set -e
set -x



rm out.tar | true
rm -rf ./tmp

mkdir ./tmp

IMAGE_NAME="8bd07846-7d97-4758-b7c5-7060d2471217"
docker tag testifysec/scratch@sha256:bc80d794049b44d65eaafec43780b5a6a4d9084b9f46d4e5b189db496c91e357 ttl.sh/$IMAGE_NAME:5h
rekorserver="http://172.23.0.3:30331"

ip=`kubectl get svc rekor-server --template="{{range .status.loadBalancer.ingress}}{{.ip}}{{end}}"`
port=`kubectl get svc rekor-server --template="{{range .spec.ports}}{{.nodePort}}{{end}}"`


#test
witness run -s=build -k testkey.pem -a oci -o attestation.json -r http://${ip}:${port} -- bash -c "docker save ttl.sh/$IMAGE_NAME:5h > ./tmp/out.tar" | true
echo "verify attestation offline"
witness verify -k testpub.pem -p policy-signed.json -a attestation.json -f ./tmp/out.tar

echo "verify attestation online"
witness verify -k testpub.pem -p policy-signed.json -r http://${ip}:${port} -f ./tmp/out.tar





