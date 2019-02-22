/*******************************************************************************
 * Copyright 2018 Dell Inc.
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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dghubble/sling"
	"github.com/hashicorp/vault/api"
)

func initVault(c *api.Sys, path string, inited bool, secretType SecretReader) (string, error) {

	if inited == false {
		ir := &api.InitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		}

		resp, err := c.Init(ir)

		vaultSecretBytes, _ := json.Marshal(resp)

		// seal the vault secrets with security / TPM device
		if sealErr := secretType.SealVaultSecrets(vaultSecretBytes, path); sealErr != nil {
			err = sealErr
		} else {
			lc.Info("Vault's secrets have been sealed securely")
		}

		lc.Info(string(vaultSecretBytes))
		lc.Info("Vault has been initialized successfully.")

		return resp.KeysB64[0], err
	}
	s, err := getSecret(path, secretType)
	if err != nil {
		return "", err
	}
	lc.Info("Vault has been initialized previously. Loading the access token for unsealling.")
	return s.Token, nil
}

func unsealVault(c *api.Sys, token string) (bool, error) {
	if len(token) == 0 {
		return true, errors.New("error:empty token")
	}
	r, err := c.SealStatus()
	if err != nil {
		lc.Error(err.Error())
		return true, err
	}
	if r.Sealed == false {
		lc.Info("Vault is in unseal status, nothing to do.")
		return false, err
	}
	resp, err := c.Unseal(token)
	if err != nil {
		fmt.Println(err.Error())
		return true, err
	}
	return resp.Sealed, err
}

func checkProxyCerts(config *tomlConfig, secretBaseURL string, c *http.Client, secretType SecretReader) (bool, error) {
	cert, key, err := getCertKeyPair(config, secretBaseURL, c, secretType)
	if err != nil {
		return false, err
	}
	if len(cert) > 0 && len(key) > 0 {
		return true, nil
	}
	return false, nil
}

/*
 curl --header "X-Vault-Token: ${_ROOT_TOKEN}" \
            --header "Content-Type: application/json" \
            --request POST \
            --data @${_PAYLOAD_KONG} \
            http://localhost:8200/v1/secret/edgex/pki/tls/edgex-kong
*/
func uploadProxyCerts(config *tomlConfig, secretBaseURL string, cert string, sk string, c *http.Client, secretType SecretReader) (bool, error) {
	body := &CertPair{
		Cert: cert,
		Key:  sk,
	}

	// TODO (just a note--thinking this is Kong Cert)
	t, err := getSecret(config.SecretService.TokenPath, secretType)
	if err != nil {
		lc.Error(err.Error())
		return false, err
	}
	lc.Info("Trying to upload cert&key to secret store.")
	s := sling.New().Set(VaultToken, t.Token)
	req, err := s.New().Base(secretBaseURL).Post(config.SecretService.CertPath).BodyJSON(body).Request()
	resp, err := c.Do(req)
	if err != nil {
		lc.Error("Failed to upload cert to secret store with error %s", err.Error())
		return false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 204 {
		lc.Info("Successful to add certificate to the secret store.")
	} else {
		b, _ := ioutil.ReadAll(resp.Body)
		s := fmt.Sprintf("Failed to add certificate to the secret store with error %s,%s.", resp.Status, string(b))
		lc.Error(s)
		return false, errors.New(s)
	}
	return true, nil
}
