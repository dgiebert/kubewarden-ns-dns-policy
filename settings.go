package main

import (
	"embed"
	"strings"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"

	"fmt"
)

//go:embed tlds-alpha-by-domain.txt
var fs embed.FS

// The Settings class is defined inside of the `types.go` file

// No special checks have to be done
func (s *Settings) Valid() (bool, error) {
	return true, nil
}

func (s *Settings) IsNameDenied(name string) bool {
	for _, deniedName := range s.DeniedTLDs {
		if strings.EqualFold(deniedName, name) {
			return true
		}
	}

	return false
}

func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	settings := Settings{}
	err := easyjson.Unmarshal(validationReq.Settings, &settings)
	if len(settings.DeniedTLDs) == 0 {
		content, _ := fs.ReadFile("tlds-alpha-by-domain.txt")
		settings.DeniedTLDs = strings.Split(string(content), "\n")[1:]
	}
	return settings, err
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings := Settings{}
	err := easyjson.Unmarshal(payload, &settings)
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}
	if valid {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(kubewarden.Message("Provided settings are not valid"))
}
