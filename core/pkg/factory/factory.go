/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package factory

import (
	"log"
	"strings"

	"github.com/edgexfoundry/security-secret-store/core/internal/secret"
)

// NewSecretType instantiates the concret instance of SecretHandler
// based on the input secretType string
func NewSecretType(secretType string) secret.SecretHandler {
	secretTypeLower := strings.ToLower(secretType)
	switch secretTypeLower {
	case "tpm":
		return secret.TPM{}
	case "plaintext":
		return secret.PlainText{}
	default:
		log.Printf("unknown secret type '%s' requested, Supported secret types are  Plain & TPM. Hence switching to default type plain", secretType)
		return secret.PlainText{}
	}
}
