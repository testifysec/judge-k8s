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
	defer f.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to open public key file: %v", err)
	}

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

func (wp *WitnessPolicy) Verify(imageRef string) (error, []string) {
	m, err := wp.getManifest(imageRef)
	if err != nil {
		return fmt.Errorf("failed to get manifest: %v", err), nil
	}

	configDigest, err := m.GetConfigDigest()
	if err != nil {
		return fmt.Errorf("failed to get config digest: %v", err), nil
	}

	err = wp.getRekorEntries(configDigest.String())
	if err != nil {
		return fmt.Errorf("failed to get rekor entry: %v", err), nil
	}

	if !wp.doesPassWitnessPolicy() {
		return fmt.Errorf("failed to pass witness policy"), nil
	}

	entryStrings := []string{}

	for _, entry := range wp.Entries {
		entryStrings = append(entryStrings, *entry.LogID)
	}

	return nil, entryStrings

}

func (wp *WitnessPolicy) getManifest(imageRef string) (manifest.Manifest, error) {
	ctx := context.Background()

	r, err := types.NewRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create ref: %v", err)
	}

	m, err := wp.RegClient.ManifestGet(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %v", err)
	}

	return m, nil
}

func (wp *WitnessPolicy) getRekorEntries(containerID string) error {
	ds := cryptoutil.DigestSet{}
	containerID = strings.Replace(containerID, "sha256:", "", -1)
	ds[crypto.SHA256] = containerID
	log.Debug("Looking up rekor for ContainerID: %s", containerID)
	entries, err := wp.Rekor.FindEntriesBySubject(ds)
	if err != nil {
		return fmt.Errorf("error finding entries: %v", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no entries found")
	}

	for _, entry := range entries {
		log.Debug("Found entry: %s", entry.LogID)
	}

	wp.Entries = entries
	return nil

}

func (wp *WitnessPolicy) doesPassWitnessPolicy() bool {
	policyEnvelope := dsse.Envelope{}
	decoder := json.NewDecoder(strings.NewReader(string(wp.Policy)))
	if err := decoder.Decode(&policyEnvelope); err != nil {
		log.Error("failed to decode policy: %v", err)
		return false
	}

	envelopes := make([]dsse.Envelope, 0)

	for _, entry := range wp.Entries {
		env, err := rekor.ParseEnvelopeFromEntry(entry)
		if err != nil {
			log.Error("failed to parse envelope from entry: %v", err)
			return false
		}
		envelopes = append(envelopes, env)
	}

	if len(envelopes) == 0 {
		log.Error("no envelopes found")
		return false
	}

	pubKeyReader := strings.NewReader(string(wp.PublicKey))

	verifier, err := cryptoutil.NewVerifierFromReader(pubKeyReader)
	if err != nil {
		fmt.Printf("failed to create verifier: %v", err)
		return false
	}

	err = witness.Verify(policyEnvelope, []cryptoutil.Verifier{verifier}, witness.VerifyWithCollectionEnvelopes(envelopes))
	if err == nil {
		return true
	}

	return false
}
