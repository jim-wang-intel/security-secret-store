/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package secret

// SecretHandler intefaces the process of wrapping (or sealing) and
// un-wrapping (or unsealing) the underneath secrets of secure storage
type SecretHandler interface {
	// SealVaultSecrets is to seal or bind the secret data of Vault, which includes
	// key shares and root token- the encryptedOutputFile is to specify the output
	// encrypted file path and name; returns error if any during the seal process
	SealVaultSecrets(secretDataBytes []byte, encryptedOutputFile string) error

	// UnsealVaultSecrets is to unseal or unbind the secret data of Vault
	// (not the secrets inside the vault but the secrets to unlock the Vault,
	// like master key and root token as examples)
	// the first return is the vault's secret data (both keys and root token)
	// the second return is any error during the unsealing process
	UnsealVaultSecrets(vaultSecretFile string) ([]byte, error)
}
