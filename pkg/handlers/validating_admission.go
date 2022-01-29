package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/testifysec/judge-k8s/cmd/options"
	"github.com/testifysec/judge-k8s/pkg/rules"

	"github.com/labstack/echo"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getWitnessPolicy(policyFile string) ([]byte, error) {
	f, err := os.Open(policyFile)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	policy, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return policy, nil

}

func PostValidatingAdmission(o options.ServeOptions) echo.HandlerFunc {
	return func(c echo.Context) error {

		var admissionReviewReq admv1.AdmissionReview
		c.Bind(&admissionReviewReq)
		podRaw := admissionReviewReq.Request.Object.Raw
		pod := &v1.Pod{}
		if err := json.Unmarshal(podRaw, pod); err != nil {
			return err
		}

		annotations := pod.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}

		rekorStrings := []string{}
		admissionResponse := admv1.AdmissionResponse{}

		for _, container := range pod.Spec.Containers {
			wp, err := rules.New(&o)
			if err != nil {
				fmt.Printf("failed to create witness policy: %v", err)
				c.Logger().Errorf("Something went wrong while creating witness policy: %+v", err)
				return c.JSON(http.StatusBadRequest, err)
			}

			err, rekorUIDs := wp.Verify(container.Image)
			if err != nil {
				fmt.Printf("failed to verify: %v", err)
				c.Logger().Errorf("Something went wrong while verifying witness policy: %+v", err)
				admissionResponse.Allowed = false
				admissionResponse.Result = &metav1.Status{
					Message: "Images not allowed by witness policy",
				}
				break
			}

			rekorStrings = append(rekorStrings, rekorUIDs...)

		}

		for i, rekorUID := range rekorStrings {
			annotations[fmt.Sprintf("testifysec.io/rekoruid%d", i)] = rekorUID
		}

		patch, err := createPatch(pod, annotations)
		if err != nil {
			return err
		}

		pt := func() *admv1.PatchType {
			pt := admv1.PatchTypeJSONPatch
			return &pt
		}()

		admissionResponse.Allowed = true
		admissionResponse.Patch = patch
		admissionResponse.PatchType = pt
		admissionResponse.UID = admissionReviewReq.Request.UID
		admissionResponse.AuditAnnotations = annotations

		admissionReviewReq.Response = &admissionResponse

		pp, err := json.MarshalIndent(&admissionReviewReq, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(pp)

		return c.JSON(http.StatusOK, &admissionReviewReq)
	}
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

// create mutation patch for resoures
func createPatch(pod *v1.Pod, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation
	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)
	spew.Dump(patch)
	return json.Marshal(patch)
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}
