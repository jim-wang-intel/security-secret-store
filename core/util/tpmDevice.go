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

package util

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// TPMDevice is the structure to interact with the TPM2 device with predefined device path
type TPMDevice struct {
	devicePath *string
}

// NewTPMDevice instantiates a pointer to TPMDevice instance
func NewTPMDevice(devPath *string) *TPMDevice {
	if devPath != nil {
		normalizedPath := strings.TrimSpace(*devPath)
		return &TPMDevice{devicePath: &normalizedPath}
	}
	return nil
}

// GetDevicePath returns the devicePath of TPMDevice
func (tpmDev *TPMDevice) GetDevicePath() *string {
	return tpmDev.devicePath
}

// OpenTPMDevice connects to the TPM2 device via the given path: returns ReadWriterCloser handler if succeeds; error otherwise
func (tpmDev *TPMDevice) OpenTPMDevice() (io.ReadWriteCloser, error) {
	return openDeviceTPM(tpmDev.devicePath)
}

func (tpmDev *TPMDevice) IsDeviceAvailable() bool {
	rw, err := tpm2.OpenTPM(*tpmDev.devicePath)
	if rw != nil {
		defer rw.Close()
	}
	if err != nil {
		return false
	}
	return true
}

func openDeviceTPM(tpmPath *string) (io.ReadWriteCloser, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, fmt.Errorf("open TPM at %s failed: %s", *tpmPath, err)
	}
	return rw, nil
}
