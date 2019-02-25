/*
 * Copyright (C) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
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
