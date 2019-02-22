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

// UnsealCACertificate implements the secretHandler to statisfy ther interface.
func (p PlainText) UnsealCACertificate(caCertFile string) ([]byte, error) {
	return nil, nil
}
