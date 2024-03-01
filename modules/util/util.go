// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package util

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"code.gitea.io/gitea/modules/optional"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// OptionalBool a boolean that can be "null"
type OptionalBool byte

const (
	// OptionalBoolNone a "null" boolean value
	_ OptionalBool = iota
	// OptionalBoolTrue a "true" boolean value
	OptionalBoolTrue
	// OptionalBoolFalse a "false" boolean value
	OptionalBoolFalse
)

// IsTrue return true if equal to OptionalBoolTrue
func (o OptionalBool) IsTrue() bool {
	return o == OptionalBoolTrue
}

// ToGeneric converts OptionalBool to optional.Option[bool]
func (o OptionalBool) ToGeneric() optional.Option[bool] {
	if o == 0 {
		return optional.None[bool]()
	}
	return optional.Some[bool](o.IsTrue())
}

// OptionalBoolFromGeneric converts optional.Option[bool] to OptionalBool
func OptionalBoolFromGeneric(o optional.Option[bool]) OptionalBool {
	if o.Has() {
		return OptionalBoolOf(o.Value())
	}
	return 0
}

// OptionalBoolOf get the corresponding OptionalBool of a bool
func OptionalBoolOf(b bool) OptionalBool {
	if b {
		return OptionalBoolTrue
	}
	return OptionalBoolFalse
}

// OptionalBoolParse get the corresponding optional.Option[bool] of a string using strconv.ParseBool
func OptionalBoolParse(s string) optional.Option[bool] {
	v, e := strconv.ParseBool(s)
	if e != nil {
		return optional.None[bool]()
	}
	return optional.Some(v)
}

// IsEmptyString checks if the provided string is empty
func IsEmptyString(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

// NormalizeEOL will convert Windows (CRLF) and Mac (CR) EOLs to UNIX (LF)
func NormalizeEOL(input []byte) []byte {
	var right, left, pos int
	if right = bytes.IndexByte(input, '\r'); right == -1 {
		return input
	}
	length := len(input)
	tmp := make([]byte, length)

	// We know that left < length because otherwise right would be -1 from IndexByte.
	copy(tmp[pos:pos+right], input[left:left+right])
	pos += right
	tmp[pos] = '\n'
	left += right + 1
	pos++

	for left < length {
		if input[left] == '\n' {
			left++
		}

		right = bytes.IndexByte(input[left:], '\r')
		if right == -1 {
			copy(tmp[pos:], input[left:])
			pos += length - left
			break
		}
		copy(tmp[pos:pos+right], input[left:left+right])
		pos += right
		tmp[pos] = '\n'
		left += right + 1
		pos++
	}
	return tmp[:pos]
}

// CryptoRandomInt returns a crypto random integer between 0 and limit, inclusive
func CryptoRandomInt(limit int64) (int64, error) {
	rInt, err := rand.Int(rand.Reader, big.NewInt(limit))
	if err != nil {
		return 0, err
	}
	return rInt.Int64(), nil
}

const alphanumericalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// CryptoRandomString generates a crypto random alphanumerical string, each byte is generated by [0,61] range
func CryptoRandomString(length int64) (string, error) {
	buf := make([]byte, length)
	limit := int64(len(alphanumericalChars))
	for i := range buf {
		num, err := CryptoRandomInt(limit)
		if err != nil {
			return "", err
		}
		buf[i] = alphanumericalChars[num]
	}
	return string(buf), nil
}

// CryptoRandomBytes generates `length` crypto bytes
// This differs from CryptoRandomString, as each byte in CryptoRandomString is generated by [0,61] range
// This function generates totally random bytes, each byte is generated by [0,255] range
func CryptoRandomBytes(length int64) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	return buf, err
}

// ToUpperASCII returns s with all ASCII letters mapped to their upper case.
func ToUpperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// ToTitleCase returns s with all english words capitalized
func ToTitleCase(s string) string {
	// `cases.Title` is not thread-safe, do not use global shared variable for it
	return cases.Title(language.English).String(s)
}

// ToTitleCaseNoLower returns s with all english words capitalized without lower-casing
func ToTitleCaseNoLower(s string) string {
	// `cases.Title` is not thread-safe, do not use global shared variable for it
	return cases.Title(language.English, cases.NoLower).String(s)
}

// ToInt64 transform a given int into int64.
func ToInt64(number any) (int64, error) {
	var value int64
	switch v := number.(type) {
	case int:
		value = int64(v)
	case int8:
		value = int64(v)
	case int16:
		value = int64(v)
	case int32:
		value = int64(v)
	case int64:
		value = v

	case uint:
		value = int64(v)
	case uint8:
		value = int64(v)
	case uint16:
		value = int64(v)
	case uint32:
		value = int64(v)
	case uint64:
		value = int64(v)

	case float32:
		value = int64(v)
	case float64:
		value = int64(v)

	case string:
		var err error
		if value, err = strconv.ParseInt(v, 10, 64); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unable to convert %v to int64", number)
	}
	return value, nil
}

// ToFloat64 transform a given int into float64.
func ToFloat64(number any) (float64, error) {
	var value float64
	switch v := number.(type) {
	case int:
		value = float64(v)
	case int8:
		value = float64(v)
	case int16:
		value = float64(v)
	case int32:
		value = float64(v)
	case int64:
		value = float64(v)

	case uint:
		value = float64(v)
	case uint8:
		value = float64(v)
	case uint16:
		value = float64(v)
	case uint32:
		value = float64(v)
	case uint64:
		value = float64(v)

	case float32:
		value = float64(v)
	case float64:
		value = v

	case string:
		var err error
		if value, err = strconv.ParseFloat(v, 64); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unable to convert %v to float64", number)
	}
	return value, nil
}

// ToPointer returns the pointer of a copy of any given value
func ToPointer[T any](val T) *T {
	return &val
}
