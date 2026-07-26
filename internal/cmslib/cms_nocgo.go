// SPDX-License-Identifier: GPL-3.0-only

//go:build !cgo

package cmslib

import "errors"

var errUnavailable = errors.New("this command requires a CGO build linked with OpenSSL libcrypto")

func Available() bool                                 { return false }
func LibraryVersion() string                          { return "unavailable (CGO disabled)" }
func EncryptPassword(string, string, []byte) error    { return errUnavailable }
func DecryptPassword(string, string, []byte) error    { return errUnavailable }
func EncryptKey(string, string, []byte, string) error { return errUnavailable }
func DecryptKey(string, string, []byte) error         { return errUnavailable }
