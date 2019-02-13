/*
 * INTEL CONFIDENTIAL
 * Copyright (2018-2019) Intel Corporation.
 *
 * The source code contained or described herein and all documents related to the source code ("Material")
 * are owned by Intel Corporation or its suppliers or licensors. Title to the Material remains with
 * Intel Corporation or its suppliers and licensors. The Material may contain trade secrets and proprietary
 * and confidential information of Intel Corporation and its suppliers and licensors, and is protected by
 * worldwide copyright and trade secret laws and treaty provisions. No part of the Material may be used,
 * copied, reproduced, modified, published, uploaded, posted, transmitted, distributed, or disclosed in
 * any way without Intel/'s prior express written permission.
 * No license under any patent, copyright, trade secret or other intellectual property right is granted
 * to or conferred upon you by disclosure or delivery of the Materials, either expressly, by implication,
 * inducement, estoppel or otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 * Unless otherwise agreed by Intel in writing, you may not remove or alter this notice or any other
 * notice embedded in Materials by Intel or Intel's suppliers or licensors in any way.
 */

package main

// SecretReader intefaces the process of wrapping (or sealing) and
// un-wrapping (or unsealing) the underneath secrets of secure storage
type SecretReader interface {
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

	// UnsealCACertificate is to unseal the Certificate Authority (CA) certificate
	// the first return is the certificate PEM bytes after unsealing process
	// the second return is any error associated with the unsealing process
	UnsealCACertificate() ([]byte, error)
}
