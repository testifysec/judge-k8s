package rules

import (
	"context"
	"crypto"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/rekor"
)

func DoesPassWitnessPolicy(image string, policy []byte) (bool, error) {
	getManifest(image)
	return true, nil
}

func getManifest(image string) manifest.Manifest {

	rc := regclient.NewRegClient()
	ctx := context.Background()

	r, err := types.NewRef(image)
	if err != nil {
		fmt.Println(err)
	}

	m, err := rc.ManifestGet(ctx, r)
	if err != nil {
		fmt.Println(err)
	}

	configDigest, err := m.GetConfigDigest()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf(" ContainerID: %s\n", configDigest)

	getRekorEntry(configDigest.String())
	return m
}

func getRekorEntry(containerID string) {
	r, err := rekor.New("http://rekor-server:8077")
	if err != nil {
		fmt.Println(err)
	}

	ds := cryptoutil.DigestSet{}

	ds[crypto.SHA256] = containerID

	spew.Dump(ds)

	fmt.Printf("Looking up rekor for ContainerID: %s\n", containerID)

	rekorEntry, err := r.FindEntriesBySubject(ds)
	if err != nil {
		fmt.Println(err)
	}

	spew.Dump(rekorEntry)

	entry, err := r.FindEntriesBySubject(ds)
	if err != nil {
		fmt.Println(err)
	}

	spew.Dump(entry)

}
