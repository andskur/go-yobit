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
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

const (
	nonceFile = "data/nonce"
)

func (y *Yobit) GetAndIncrementNonce() (nonce uint64) {
	y.mutex.Lock()
	defer y.mutex.Unlock()
	nonce = readNonce()
	incrementNonce(&nonce)
	return
}

func readNonce() (nonce uint64) {
	CreateNonceFileIfNotExists()
	data, e := ioutil.ReadFile(nonceFile)
	if e != nil {
		panic(fmt.Errorf("nonce file read error"))
	}
	nonce, conErr := strconv.ParseUint(string(data), 10, 64)
	if conErr != nil {
		panic(conErr)
	}
	return
}

func WriteNonce(data []byte) {
	if err := ioutil.WriteFile(nonceFile, data, 0644); err != nil {
		panic(err)
	}
}

func incrementNonce(nonceOld *uint64) {
	*nonceOld = *nonceOld + 1
	ns := strconv.FormatUint(*nonceOld, 10)
	WriteNonce([]byte(ns))
}

func CreateNonceFileIfNotExists() {
	if _, err := os.Stat(nonceFile); os.IsNotExist(err) {
		if _, err = os.Create(nonceFile); err != nil {
			panic(err)
		}
		d1 := []byte("1")
		WriteNonce(d1)
	}
}

func signHmacSha512(secret []byte, message []byte) (digest string) {
	mac := hmac.New(sha512.New, secret)
	mac.Write(message)
	digest = hex.EncodeToString(mac.Sum(nil))
	return
}
