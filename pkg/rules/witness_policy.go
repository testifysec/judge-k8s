package rules

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/labstack/gommon/log"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/testifysec/judge-k8s/cmd/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/rekor"
)

type WitnessPolicy struct {
	Manifest  manifest.Manifest
	Entries   []*models.LogEntryAnon
	Rekor     rekor.RekorClient
	RegClient regclient.RegClient
	Policy    []byte
	PublicKey []byte
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

	r, err := rekor.New(o.RekorServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create rekor client: %v", err)
	}
	wp.Rekor = r
	return wp, nil
}

func (wp *WitnessPolicy) Verify(imageRef string) ([]string, error) {
	m, err := wp.getManifest(imageRef)
	if err != nil {
		fmt.Printf("failed to get manifest: %v", err)
		return nil, fmt.Errorf("failed to get manifest: %v", err)
	}

	configDigest, err := m.GetConfigDigest()
	if err != nil {
		fmt.Printf("failed to get config digest: %v", err)
		return nil, fmt.Errorf("failed to get config digest: %v", err)
	}

	err = wp.getRekorEntries(configDigest.String())
	if err != nil {
		fmt.Printf("failed to get rekor entries: %v", err)
		return nil, fmt.Errorf("failed to get rekor entries: %v", err)
	}

	entryStrings := []string{}

	for _, entry := range wp.Entries {
		entryStrings = append(entryStrings, *entry.LogID)
	}

	err = wp.doesPassWitnessPolicy()
	if err != nil {
		return entryStrings, err
	}

	//Passes all checks
	return entryStrings, nil

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
	entries, err := wp.Rekor.FindEntriesBySubject(ds)
	if err != nil {
		return fmt.Errorf("failed to get rekor entries: %v", err)
	}

	if len(entries) == 0 {
		fmt.Printf("No entries found for ContainerID: %s", containerID)
		return fmt.Errorf("no entries found")
	}

	for _, entry := range entries {
		wp.Entries = append(wp.Entries, entry)
		log.Debug("Found entry: %s", entry.LogID)
	}
	return nil

}

func (wp *WitnessPolicy) doesPassWitnessPolicy() error {
	policyEnvelope := dsse.Envelope{}
	decoder := json.NewDecoder(strings.NewReader(string(wp.Policy)))
	if err := decoder.Decode(&policyEnvelope); err != nil {
		return fmt.Errorf("failed to decode policy: %v", err)
	}

	envelopes := make([]dsse.Envelope, 0)

	for _, entry := range wp.Entries {
		env, err := rekor.ParseEnvelopeFromEntry(entry)
		if err != nil {
			return fmt.Errorf("failed to parse envelope: %v", err)
		}
		envelopes = append(envelopes, env)
	}

	if len(envelopes) == 0 {
		return fmt.Errorf("no envelopes found")
	}

	pubKeyReader := strings.NewReader(string(wp.PublicKey))

	verifier, err := cryptoutil.NewVerifierFromReader(pubKeyReader)
	if err != nil {
		return err
	}

	reason := witness.Verify(policyEnvelope, []cryptoutil.Verifier{verifier}, witness.VerifyWithCollectionEnvelopes(envelopes))
	if reason == nil {

		//Policy Passed
		return nil
	}

	return fmt.Errorf("policy failed to verify: %v", reason)
}
