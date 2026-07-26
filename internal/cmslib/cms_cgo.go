// SPDX-License-Identifier: GPL-3.0-only

//go:build cgo

package cmslib

/*
#cgo pkg-config: openssl
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void cw_set_error(char *buffer, size_t length, const char *fallback) {
	unsigned long code = ERR_get_error();
	if (code != 0) {
		ERR_error_string_n(code, buffer, length);
		return;
	}
	snprintf(buffer, length, "%s", fallback);
}

static void cw_clear_free(void *value, size_t length) {
	if (value != NULL) {
		OPENSSL_cleanse(value, length);
		free(value);
	}
}

static int cw_password_encrypt(
	const char *input_path,
	const char *output_path,
	const unsigned char *password,
	size_t password_length,
	int iterations,
	char *error_buffer,
	size_t error_length
) {
	int result = 0;
	BIO *input = NULL;
	BIO *output = NULL;
	CMS_ContentInfo *cms = NULL;
	CMS_RecipientInfo *recipient = NULL;
	EVP_CIPHER *content_cipher = NULL;
	EVP_CIPHER *kek_cipher = NULL;
	unsigned char *password_copy = NULL;

	ERR_clear_error();
	input = BIO_new_file(input_path, "rb");
	output = BIO_new_file(output_path, "wb");
	content_cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
	kek_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
	if (input == NULL || output == NULL || content_cipher == NULL || kek_cipher == NULL)
		goto cleanup;

	cms = CMS_encrypt_ex(NULL, NULL, content_cipher,
		CMS_BINARY | CMS_PARTIAL | CMS_STREAM, NULL, NULL);
	if (cms == NULL)
		goto cleanup;

	password_copy = OPENSSL_memdup(password, password_length);
	if (password_copy == NULL && password_length != 0)
		goto cleanup;

	recipient = CMS_add0_recipient_password(
		cms, iterations, NID_undef, NID_undef,
		password_copy, (ossl_ssize_t)password_length, kek_cipher);
	if (recipient == NULL)
		goto cleanup;

	if (i2d_CMS_bio_stream(output, cms, input, CMS_BINARY | CMS_STREAM) != 1)
		goto cleanup;
	if (BIO_flush(output) != 1)
		goto cleanup;
	result = 1;

cleanup:
	if (recipient != NULL && password_copy != NULL)
		CMS_RecipientInfo_set0_password(recipient, NULL, 0);
	if (password_copy != NULL)
		OPENSSL_clear_free(password_copy, password_length);
	if (!result)
		cw_set_error(error_buffer, error_length, "CMS password encryption failed");
	CMS_ContentInfo_free(cms);
	EVP_CIPHER_free(content_cipher);
	EVP_CIPHER_free(kek_cipher);
	BIO_free(input);
	BIO_free(output);
	return result;
}

static int cw_password_decrypt(
	const char *input_path,
	const char *output_path,
	const unsigned char *password,
	size_t password_length,
	char *error_buffer,
	size_t error_length
) {
	int result = 0;
	BIO *input = NULL;
	BIO *output = NULL;
	CMS_ContentInfo *cms = NULL;
	unsigned char *password_copy = NULL;

	ERR_clear_error();
	input = BIO_new_file(input_path, "rb");
	output = BIO_new_file(output_path, "wb");
	if (input == NULL || output == NULL)
		goto cleanup;
	cms = d2i_CMS_bio(input, NULL);
	if (cms == NULL)
		goto cleanup;
	password_copy = OPENSSL_memdup(password, password_length);
	if (password_copy == NULL && password_length != 0)
		goto cleanup;
	if (CMS_decrypt_set1_password(cms, password_copy, (ossl_ssize_t)password_length) != 1)
		goto cleanup;
	if (CMS_decrypt(cms, NULL, NULL, NULL, output, CMS_BINARY) != 1)
		goto cleanup;
	if (BIO_flush(output) != 1)
		goto cleanup;
	result = 1;

cleanup:
	if (password_copy != NULL)
		OPENSSL_clear_free(password_copy, password_length);
	if (!result)
		cw_set_error(error_buffer, error_length, "CMS password decryption failed");
	CMS_ContentInfo_free(cms);
	BIO_free(input);
	BIO_free(output);
	return result;
}

static int cw_key_encrypt(
	const char *input_path,
	const char *output_path,
	const unsigned char *key,
	size_t key_length,
	const char *cipher_name,
	char *error_buffer,
	size_t error_length
) {
	int result = 0;
	BIO *input = NULL;
	BIO *output = NULL;
	CMS_ContentInfo *cms = NULL;
	CMS_RecipientInfo *recipient = NULL;
	EVP_CIPHER *cipher = NULL;
	unsigned char *key_copy = NULL;
	unsigned char *key_id = NULL;
	int wrap_nid = NID_undef;

	ERR_clear_error();
	input = BIO_new_file(input_path, "rb");
	output = BIO_new_file(output_path, "wb");
	cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
	if (input == NULL || output == NULL || cipher == NULL)
		goto cleanup;
	switch (key_length) {
	case 16:
		wrap_nid = NID_id_aes128_wrap;
		break;
	case 24:
		wrap_nid = NID_id_aes192_wrap;
		break;
	case 32:
		wrap_nid = NID_id_aes256_wrap;
		break;
	default:
		goto cleanup;
	}
	cms = CMS_encrypt_ex(NULL, NULL, cipher,
		CMS_BINARY | CMS_PARTIAL | CMS_STREAM, NULL, NULL);
	if (cms == NULL)
		goto cleanup;
	key_copy = OPENSSL_memdup(key, key_length);
	key_id = OPENSSL_malloc(16);
	if (key_copy == NULL || key_id == NULL)
		goto cleanup;
	if (RAND_bytes(key_id, 16) != 1)
		goto cleanup;
	recipient = CMS_add0_recipient_key(
		cms, wrap_nid, key_copy, key_length, key_id, 16, NULL, NULL, NULL);
	if (recipient == NULL)
		goto cleanup;
	if (i2d_CMS_bio_stream(output, cms, input, CMS_BINARY | CMS_STREAM) != 1)
		goto cleanup;
	if (BIO_flush(output) != 1)
		goto cleanup;
	result = 1;

cleanup:
	if (recipient != NULL && key_copy != NULL)
		CMS_RecipientInfo_set0_key(recipient, NULL, 0);
	if (key_copy != NULL)
		OPENSSL_clear_free(key_copy, key_length);
	if (recipient == NULL && key_id != NULL)
		OPENSSL_free(key_id);
	if (!result)
		cw_set_error(error_buffer, error_length, "CMS symmetric-key encryption failed");
	CMS_ContentInfo_free(cms);
	EVP_CIPHER_free(cipher);
	BIO_free(input);
	BIO_free(output);
	return result;
}

static int cw_key_decrypt(
	const char *input_path,
	const char *output_path,
	const unsigned char *key,
	size_t key_length,
	char *error_buffer,
	size_t error_length
) {
	int result = 0;
	BIO *input = NULL;
	BIO *output = NULL;
	CMS_ContentInfo *cms = NULL;

	ERR_clear_error();
	input = BIO_new_file(input_path, "rb");
	output = BIO_new_file(output_path, "wb");
	if (input == NULL || output == NULL)
		goto cleanup;
	cms = d2i_CMS_bio(input, NULL);
	if (cms == NULL)
		goto cleanup;
	if (CMS_decrypt_set1_key(cms, (unsigned char *)key, key_length, NULL, 0) != 1)
		goto cleanup;
	if (CMS_decrypt(cms, NULL, NULL, NULL, output, CMS_BINARY) != 1)
		goto cleanup;
	if (BIO_flush(output) != 1)
		goto cleanup;
	result = 1;

cleanup:
	if (!result)
		cw_set_error(error_buffer, error_length, "CMS symmetric-key decryption failed");
	CMS_ContentInfo_free(cms);
	BIO_free(input);
	BIO_free(output);
	return result;
}

static const char *cw_library_version(void) {
	return OpenSSL_version(OPENSSL_VERSION);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const passwordIterations = 1_400_000

func Available() bool { return true }

func LibraryVersion() string {
	return C.GoString(C.cw_library_version())
}

func EncryptPassword(input, output string, password []byte) error {
	return withPathsAndSecret(input, output, password, func(
		cInput, cOutput *C.char, secret *C.uchar, length C.size_t, errbuf *C.char, errlen C.size_t,
	) C.int {
		return C.cw_password_encrypt(
			cInput, cOutput, secret, length, C.int(passwordIterations), errbuf, errlen)
	})
}

func DecryptPassword(input, output string, password []byte) error {
	return withPathsAndSecret(input, output, password, func(
		cInput, cOutput *C.char, secret *C.uchar, length C.size_t, errbuf *C.char, errlen C.size_t,
	) C.int {
		return C.cw_password_decrypt(cInput, cOutput, secret, length, errbuf, errlen)
	})
}

func EncryptKey(input, output string, key []byte, cipher string) error {
	cCipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(cCipher))
	return withPathsAndSecret(input, output, key, func(
		cInput, cOutput *C.char, secret *C.uchar, length C.size_t, errbuf *C.char, errlen C.size_t,
	) C.int {
		return C.cw_key_encrypt(cInput, cOutput, secret, length, cCipher, errbuf, errlen)
	})
}

func DecryptKey(input, output string, key []byte) error {
	return withPathsAndSecret(input, output, key, func(
		cInput, cOutput *C.char, secret *C.uchar, length C.size_t, errbuf *C.char, errlen C.size_t,
	) C.int {
		return C.cw_key_decrypt(cInput, cOutput, secret, length, errbuf, errlen)
	})
}

type cOperation func(*C.char, *C.char, *C.uchar, C.size_t, *C.char, C.size_t) C.int

func withPathsAndSecret(input, output string, secret []byte, operation cOperation) error {
	if len(secret) == 0 {
		return errors.New("secret must not be empty")
	}
	cInput := C.CString(input)
	cOutput := C.CString(output)
	cSecret := C.CBytes(secret)
	defer C.free(unsafe.Pointer(cInput))
	defer C.free(unsafe.Pointer(cOutput))
	defer C.cw_clear_free(cSecret, C.size_t(len(secret)))
	errorBuffer := make([]byte, 512)
	result := operation(
		cInput,
		cOutput,
		(*C.uchar)(cSecret),
		C.size_t(len(secret)),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])),
		C.size_t(len(errorBuffer)),
	)
	if result != 1 {
		message := C.GoString((*C.char)(unsafe.Pointer(&errorBuffer[0])))
		return fmt.Errorf("%s", message)
	}
	return nil
}
