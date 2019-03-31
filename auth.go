/*
 * MIT License
 *
 * Copyright (c) 2018 Igor Konovalov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package yobit

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
)

const (
	nonceFile = "data/nonce"
)

var (
	errREadNonceFile = errors.New("nonce file read error")
)

func (y *Yobit) GetAndIncrementNonce() (nonce uint64, err error) {
	y.mutex.Lock()
	defer y.mutex.Unlock()
	nonce, err = readNonce()
	if err != nil {
		return
	}
	err = incrementNonce(&nonce)
	return
}

func readNonce() (nonce uint64, err error) {
	if err = CreateNonceFileIfNotExists(); err != nil {
		return
	}
	data, err := ioutil.ReadFile(nonceFile)
	if err != nil {
		return 0, errREadNonceFile
	}
	nonce, err = strconv.ParseUint(string(data), 10, 64)
	return
}
func WriteNonce(data []byte) (err error) {
	err = ioutil.WriteFile(nonceFile, data, 0644)
	return
}

func incrementNonce(nonceOld *uint64) (err error) {
	*nonceOld = *nonceOld + 1
	ns := strconv.FormatUint(*nonceOld, 10)
	err = WriteNonce([]byte(ns))
	return
}

func CreateNonceFileIfNotExists() (err error) {
	if _, err = os.Stat(nonceFile); os.IsNotExist(err) {
		if _, err = os.Create(nonceFile); err != nil {
			return err
		}
		d1 := []byte("1")
		err = WriteNonce(d1)
		return
	}
	return err
}

func signHmacSha512(secret []byte, message []byte) (digest string) {
	mac := hmac.New(sha512.New, secret)
	mac.Write(message)
	digest = hex.EncodeToString(mac.Sum(nil))
	return
}
