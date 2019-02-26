/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package factory

import (
	"testing"

	"github.com/edgexfoundry/security-secret-store/core/internal/secret"
	"github.com/stretchr/testify/assert"
)

func TestNewSecretPlainType(t *testing.T) {

	secretType := "plaintext"
	expectedType := secret.PlainText{}

	createdType := NewSecretType(secretType)

	if assert.NotNil(t, createdType, "secret type is empty for: ", secretType) == false {
		t.Fatal()
	}
	if assert.Equal(t, expectedType, createdType, "Plain type is expected to be created") == false {
		t.Fatal()
	}
}

func TestNewSecretTPMType(t *testing.T) {

	secretType := "TPM"
	expectedType := secret.TPM{}

	createdType := NewSecretType(secretType)

	if assert.NotNil(t, createdType, "secret type is empty for: ", secretType) == false {
		t.Fatal()
	}
	if assert.Equal(t, expectedType, createdType, "Plain type is expected to be created") == false {
		t.Fatal()
	}
}

func TestNewSecretBogusType(t *testing.T) {

	secretType := "mock"
	expectedType := secret.PlainText{}

	createdType := NewSecretType(secretType)

	if assert.NotNil(t, createdType, "secret type is empty for: ", secretType) == false {
		t.Fatal()
	}
	if assert.Equal(t, expectedType, createdType, "Plain type is expected to be created for any unknown types") == false {
		t.Fatal()
	}
}
