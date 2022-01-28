package rules

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/rekor"
)

func DoesPassWitnessPolicy(image string, policy []byte) (bool, error) {
	m, err := getManifest(image)
	if err != nil {
		return false, err
	}

	configDigest, err := m.GetConfigDigest()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Requesting Rekor entyry for containerID: %s\n", configDigest)
	entries, err := getRekorEntry(configDigest.String())
	if err != nil {
		fmt.Println(err)
	}

	if err := verifyEntries(entries); err != nil {
		fmt.Println(err)
	}
	return true, nil
}

func getManifest(imageRef string) (manifest.Manifest, error) {
	rc := regclient.NewRegClient()
	ctx := context.Background()

	r, err := types.NewRef(imageRef)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	m, err := rc.ManifestGet(ctx, r)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return m, nil

}

func getRekorEntry(containerID string) ([]*models.LogEntryAnon, error) {
	r, err := rekor.New("http://rekor-server:8077")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	ds := cryptoutil.DigestSet{}
	containerID = strings.Replace(containerID, "sha256:", "", -1)

	ds[crypto.SHA256] = containerID

	fmt.Printf("Looking up rekor for ContainerID: %s\n", containerID)

	entries, err := r.FindEntriesBySubject(ds)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return entries, nil

}

func verifyEntries(entries []*models.LogEntryAnon) error {
	envelopes := []dsse.Envelope{}

	for _, entry := range entries {
		env, err := rekor.ParseEnvelopeFromEntry(entry)
		if err != nil {
			return fmt.Errorf("failed to parse envelope from entry: %v", err)
		}
		envelopes = append(envelopes, env)

	}

	if len(envelopes) == 0 {
		return fmt.Errorf("no envelopes to verify")
	}

	for _, env := range envelopes {
		fmt.Printf("Verifying envelope: %s\n", env.PayloadType)
	}

	return nil

}
