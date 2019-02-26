/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package secret

import (
	"io/ioutil"
)

type PlainText struct{}

// SealVaultSecrets writes secret to outputfile
func (p PlainText) SealVaultSecrets(dataBytes []byte, outputFile string) error {
	writeErr := ioutil.WriteFile(outputFile, dataBytes, 0644)
	if writeErr != nil {
		return writeErr
	}
	return nil
}

// UnsealVaultSecrets reads secrets from secretFile
func (p PlainText) UnsealVaultSecrets(secretFile string) ([]byte, error) {
	raw, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return raw, err
	}
	return raw, nil
}
