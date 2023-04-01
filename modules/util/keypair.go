// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// GenerateKeyPair generates a public and private keypair
func GenerateKeyPair(bits int) (string, string, error) {
	priv, _ := rsa.GenerateKey(rand.Reader, bits)
	privPem, err := pemBlockForPriv(priv)
	if err != nil {
		return "", "", err
	}
	pubPem, err := pemBlockForPub(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	return privPem, pubPem, nil
}

func pemBlockForPriv(priv *rsa.PrivateKey) (string, error) {
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return string(privBytes), nil
}

func pemBlockForPub(pub *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubBytes), nil
}
