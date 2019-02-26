/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
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

// IsDeviceAvailable tries to open TPM device and returns true if ok
// otherwise, returns false
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
