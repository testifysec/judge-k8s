package rules

import (
	"context"

	"github.com/regclient/regclient/regclient"
	"github.com/regclient/regclient/regclient/manifest"
	"github.com/regclient/regclient/regclient/types"
)

func DoesPassWitnessPolicy(image string, policy []byte) (bool, error) {
	return true, nil
}

func getManifest(image string) manifest.Manifest {
	ch := regclient.ConfigHost{
		Name:       "",
		Scheme:     "",
		TLS:        0,
		RegCert:    "",
		ClientCert: "",
		ClientKey:  "",
		DNS:        []string{},
		Hostname:   "",
		User:       "",
		Pass:       "",
		Token:      "",
		PathPrefix: "",
		Mirrors:    []string{},
		Priority:   0,
		API:        "",
		APIOpts:    map[string]string{},
		BlobChunk:  0,
		BlobMax:    0,
	}

	regclientopt := regclient.WithConfigHost(ch)
	rc := regclient.NewRegClient(regclientopt)
	ctx := context.Background()

	m, err := rc.ManifestGet(ctx, types.Ref{
		Reference:  "",
		Registry:   "",
		Repository: "",
		Tag:        "",
		Digest:     "",
	})
	if err != nil {
		return nil
	}

	return m
}
