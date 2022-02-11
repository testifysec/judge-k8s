kubectl delete deploy test || true && kubectl create deployment --image=testifysec/scratch@sha256:bc80d794049b44d65eaafec43780b5a6a4d9084b9f46d4e5b189db496c91e357 test


witness run -s save -k testkey.pem -a oci -o attestation.json -r http://172.22.0.3:30331 -- bash -c "docker save docker.io/testifysec/scratch@sha256:bc80d794049b44d65eaafec43780b5a6a4d9084b9f46d4e5b189db496c91e357 > out.tar"