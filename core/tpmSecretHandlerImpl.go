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

import "github.com/edgexfoundry/security-secret-store/core/util"

var tpmDevice *util.TPMDevice

// UnsealCACertificate implements the secretHandler interface for the hardware TPM device
// in this concrete tpmSecretReader example
func UnsealCACertificate(caCertFile string) ([]byte, error) {
	unsealInput := util.UnsealInput{
		SecretKeyFileName: &caCertFile,
	}

	caCertStr, unsealErr := util.Unseal(getTPMDevice(), unsealInput)
	if unsealErr != nil {
		return nil, unsealErr
	}
	return []byte(caCertStr), nil
}

func getTPMDevice() *util.TPMDevice {
	if tpmDevice == nil {
		// by default the hardware TPM will create this device
		tpmPath := "/dev/tpm0"
		tpmDevice = util.NewTPMDevice(&tpmPath)
	}
	return tpmDevice
}
