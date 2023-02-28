package main

import (
	"testing"

	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
	"github.com/mailru/easyjson"
)

func TestApproval(t *testing.T) {
	settings := Settings{
		DeniedTLDs: []string{"com"},
	}
	namespace := corev1.Namespace{
		Metadata: &metav1.ObjectMeta{
			Name: "test",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&namespace, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestApprovalHTTP(t *testing.T) {
	settings := Settings{
		DeniedTLDs: []string{},
	}
	namespace := corev1.Namespace{
		Metadata: &metav1.ObjectMeta{
			Name: "test",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&namespace, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection")
	}
}

func TestRejectionBecauseNameIsDenied(t *testing.T) {
	settings := Settings{
		DeniedTLDs: []string{"com"},
	}

	ns := corev1.Namespace{
		Metadata: &metav1.ObjectMeta{
			Name: "com",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ns, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expected_message := "The 'com' namespace is on the deny list"
	if response.Message == nil {
		t.Errorf("expected response to have a message")
	}
	if *response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expected_message)
	}
}

func TestRejectionBecauseNameIsDeniedHTTP(t *testing.T) {
	settings := Settings{
		DeniedTLDs: []string{},
	}

	ns := corev1.Namespace{
		Metadata: &metav1.ObjectMeta{
			Name: "com",
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ns, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Unexpected approval")
	}

	expected_message := "The 'com' namespace is on the deny list"
	if response.Message == nil {
		t.Errorf("expected response to have a message")
	}
	if *response.Message != expected_message {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expected_message)
	}
}
