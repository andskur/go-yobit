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
	"bytes"
	"encoding/gob"
	"net/http"
	"net/url"

	"github.com/syndtr/goleveldb/leveldb"
)

type LocalStorage struct {
	db *leveldb.DB
}

func NewStorage() *LocalStorage {
	ldb, err := leveldb.OpenFile("data/db", nil)
	if err != nil {
		fatal(err)
	}
	return &LocalStorage{db: ldb}
}

func (s *LocalStorage) Release() {
	s.db.Close()
}

func (s *LocalStorage) SaveCookies(url *url.URL, cookies []*http.Cookie) {
	key, _ := encode(url)
	val, _ := encode(cookies)
	s.db.Put(key, val, nil)
}

func (s *LocalStorage) LoadCookies(url *url.URL) []*http.Cookie {
	key, _ := encode(url)
	val, _ := s.db.Get(key, nil)
	var cookies []*http.Cookie
	decode(val, &cookies)
	return cookies
}

func encode(val interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(val)
	if err != nil {
		return nil, err
	}
	readyBytes := buf.Bytes()
	return readyBytes, nil
}

func decode(bVal []byte, val interface{}) error {
	bufRef := bytes.NewBuffer(bVal)
	dec := gob.NewDecoder(bufRef)
	err := dec.Decode(val)
	if err != nil {
		return err
	}
	return nil
}
