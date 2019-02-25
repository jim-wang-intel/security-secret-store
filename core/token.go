/*******************************************************************************
 * Copyright 2018 Dell Inc.
 * Copyright 2019 Intel Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * @author: Tingyu Zeng, Dell
 * @version: 0.1.0
 *******************************************************************************/

package main

import (
	"encoding/json"

	"github.com/edgexfoundry/security-secret-store/core/internal/secret"
)

type Secret struct {
	Token string `json:"root_token"`
}

func getSecret(filename string, secretType secret.SecretHandler) (Secret, error) {
	// unseal the secrets (like master key and root token) that are used to unlock the vault
	raw, unsealErr := secretType.UnsealVaultSecrets(filename)

	s := Secret{}
	if unsealErr != nil {
		return s, unsealErr
	}
	unmarshalErr := json.Unmarshal(raw, &s)
	return s, unmarshalErr
}
