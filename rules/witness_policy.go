package rules

import (
	"context"
	"fmt"

	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
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

	fmt.Printf("ContainerID: %s\n", configDigest)
	return m
}
