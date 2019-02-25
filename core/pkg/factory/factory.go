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
