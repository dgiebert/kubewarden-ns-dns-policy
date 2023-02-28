package main

import (
	"fmt"

	onelog "github.com/francoispqt/onelog"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
)

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := easyjson.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}
	// Create a Settings instance from the ValidationRequest object
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	// Access the **raw** JSON that describes the object
	rawJSON := validationRequest.Request.Object

	// Try to create a Namespace instance using the RAW JSON we got from the
	// ValidationRequest.
	ns := &corev1.Namespace{}
	if err := easyjson.Unmarshal([]byte(rawJSON), ns); err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("Cannot decode Namespace object: %s", err.Error())),
			kubewarden.Code(400))
	}

	logger.DebugWithFields("validating namespace object", func(e onelog.Entry) {
		e.String("name", ns.Metadata.Name)
	})

	if settings.IsNameDenied(ns.Metadata.Name) {
		logger.InfoWithFields("rejecting namespace object", func(e onelog.Entry) {
			e.String("name", ns.Metadata.Name)
		})

		return kubewarden.RejectRequest(
			kubewarden.Message(
				fmt.Sprintf("The '%s' namespace is on the deny list", ns.Metadata.Name)),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
