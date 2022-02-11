package rules

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
	"github.com/testifysec/judge-k8s/cmd/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/log"
	"github.com/testifysec/witness/pkg/rekor"


	// imported so their init functions run
	_ "github.com/testifysec/witness/pkg/attestation/aws-iid"
	_ "github.com/testifysec/witness/pkg/attestation/commandrun"
	_ "github.com/testifysec/witness/pkg/attestation/environment"
	_ "github.com/testifysec/witness/pkg/attestation/gcp-iit"
	_ "github.com/testifysec/witness/pkg/attestation/git"
	_ "github.com/testifysec/witness/pkg/attestation/gitlab"
	_ "github.com/testifysec/witness/pkg/attestation/jwt"
	_ "github.com/testifysec/witness/pkg/attestation/maven"
	_ "github.com/testifysec/witness/pkg/attestation/oci"

)

func init() {
	log.SetLogger(logger{})
}

type WitnessPolicy struct {
	Manifest    manifest.Manifest
	rekorServer string
	Envelopes   []dsse.Envelope
	RegClient   regclient.RegClient
	Policy      []byte
	PublicKey   []byte
}

func New(o *options.ServeOptions) (*WitnessPolicy, error) {

	wp := &WitnessPolicy{}

	f, err := os.Open(o.PublicKey)

	if err != nil {
		return nil, fmt.Errorf("failed to open public key file: %v", err)
	}
	defer f.Close()

	pubKeyBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	wp.PublicKey = pubKeyBytes

	b, err := os.ReadFile(o.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %v", err)
	}

	wp.Policy = b

	wp.RegClient = regclient.NewRegClient()

	wp.rekorServer = o.RekorServer
	return wp, nil
}

func (wp *WitnessPolicy) Verify(imageRef string) ([]string, error) {
	m, err := wp.getManifest(imageRef)
	if err != nil {
		fmt.Printf("failed to get manifest: %v\n", err)
		return nil, fmt.Errorf("failed to get manifest: %v", err)
	}

	configDigest, err := m.GetConfigDigest()
	if err != nil {
		fmt.Printf("failed to get config digest: %v\n", err)
		return nil, fmt.Errorf("failed to get config digest: %v", err)
	}

	err = wp.getRekorEntries(configDigest.String())
	if err != nil {
		fmt.Printf("failed to get rekor entries: %v=n", err)
		return nil, fmt.Errorf("failed to get rekor entries: %v", err)
	}

	err = wp.doesPassWitnessPolicy()
	if err != nil {
		fmt.Printf("failed to pass witness policy: %v\n", err)
		return []string{}, err
	}

	//Passes all checks
	return []string{}, nil

}

func (wp *WitnessPolicy) getManifest(imageRef string) (manifest.Manifest, error) {
	ctx := context.Background()

	r, err := types.NewRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create ref: %v", err)
	}

	manifest, err := wp.RegClient.ManifestGet(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %v", err)

	}

	if manifest.IsList() {

		plat := ociv1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		}

		desc, err := manifest.GetPlatformDesc(&plat)
		if err != nil {
			return nil, err
		}

		r.Digest = desc.Digest.String()
		manifest, err = wp.RegClient.ManifestGet(ctx, r)
		if err != nil {
			return nil, err
		}
	}

	return manifest, nil
}

func (wp *WitnessPolicy) getRekorEntries(containerID string) error {
	ds := cryptoutil.DigestSet{}
	containerID = strings.Replace(containerID, "sha256:", "", -1)
	ds[crypto.SHA256] = containerID
	fmt.Printf("looking up rekor entry for container id: %v", containerID)

	entries, err := loadEnvelopesFromRekor(wp.rekorServer, ds)

	if err != nil {
		return fmt.Errorf("failed to get rekor entries: %v", err)
	}

	if len(entries) == 0 {
		fmt.Printf("No entries found for ContainerID: %s", containerID)
		return fmt.Errorf("no entries found")
	}

	wp.Envelopes = entries

	return nil

}

func (wp *WitnessPolicy) doesPassWitnessPolicy() error {
	policyEnvelope := dsse.Envelope{}
	err := json.Unmarshal(wp.Policy, &policyEnvelope)

	if err != nil {

		return fmt.Errorf("failed to unmarshal policy: %v", err)
	}

	pubKeyReader := strings.NewReader(string(wp.PublicKey))

	verifier, err := cryptoutil.NewVerifierFromReader(pubKeyReader)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	veropt := witness.VerifyWithCollectionEnvelopes(wp.Envelopes)
	spew.Dump(veropt)

	reason := witness.Verify(policyEnvelope, []cryptoutil.Verifier{verifier}, veropt)

	if reason == nil {

		//Policy Passed
		return nil
	}

	keyid, err := verifier.KeyID()
	if err != nil {
		return fmt.Errorf("failed to get key id: %v", err)
	}

	fmt.Printf("Keyid: %v\n", keyid)
	fmt.Printf("PolicyKeyid: %v\n", policyEnvelope.Signatures[0].KeyID)
	fmt.Printf("attestation keyid: %v\n", wp.Envelopes[0].Signatures[0].KeyID)

	fmt.Printf("policy bytes:\n%s\n", wp.Policy)
	fmt.Printf("public key:\n%s\n", wp.PublicKey)
	for _, e := range wp.Envelopes {
		out, err := json.Marshal(e)
		if err != nil {
			fmt.Printf("failed to marshal envelope: %v", err)
		}

		fmt.Printf("envelope:\n %s\n", out)
	}
	return fmt.Errorf("policy failed to verify: %v", reason)
}

func loadEnvelopesFromRekor(rekorServer string, artifactDigestSet cryptoutil.DigestSet) ([]dsse.Envelope, error) {
	envelopes := make([]dsse.Envelope, 0)
	rc, err := rekor.New(rekorServer)
	if err != nil {
		return nil, fmt.Errorf("failed to get initialize Rekor client: %w", err)
	}

	entries, err := rc.FindEntriesBySubject(artifactDigestSet)
	if err != nil {
		return nil, fmt.Errorf("failed to find any entries in rekor: %w", err)
	}

	for _, entry := range entries {
		env, err := rekor.ParseEnvelopeFromEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dsse envelope from rekor entry: %w", err)
		}

		envelopes = append(envelopes, env)
	}

	return envelopes, nil
}

type logger struct {}


func (logger) Errorf(format string, args ...interface{}) {
	fmt.Println(fmt.Sprintf(format, args...))
}

func (logger) Error(args ...interface{}) {
	fmt.Println(args...)
}

func (logger)  Warnf(format string, args ...interface{}) {
	fmt.Println(fmt.Sprintf(format, args...))
}

func (logger) Warn(args ...interface{}) {
	fmt.Println(args...)
}

func (logger) Debugf(format string, args ...interface{}) {
	fmt.Println(fmt.Sprintf(format, args...))
}

func (logger) Debug(args ...interface{}) {
	fmt.Println(args...)
}

func (logger) Infof(format string, args ...interface{}) {
	fmt.Println(fmt.Sprintf(format, args...))
}

func (logger) Info(args ...interface{}) {
	fmt.Println(args...)
}