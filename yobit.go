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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ikonovalov/go-cloudflare-scraper"
)

const (
	Url        = "https://yobit.net"
	ApiVersion = "3"
	apiBase    = Url + "/api/"
	apiTrade   = Url + "/tapi/"
)

// errors
var (
	errTicketEmpty = errors.New("tickers24: Tickers list is empty")
)

type Yobit struct {
	site       *url.URL
	client     *http.Client
	credential *ApiCredential
	pairs      map[string]PairInfo
	mutex      sync.Mutex
	store      *LocalStorage
	logger     bool
}

func New(credential ApiCredential, logger bool) (*Yobit, error) {
	cloudflare, err := scraper.NewTransport(http.DefaultTransport)
	if err != nil {
		return nil, err
	}

	yobitUrl, err := url.Parse(Url)
	if err != nil {
		return nil, err
	}

	storage, err := NewStorage()
	if err != nil {
		return nil, err
	}

	yobit := Yobit{
		site:       yobitUrl,
		client:     &http.Client{Transport: cloudflare, Jar: cloudflare.Cookies, Timeout: time.Second * 10},
		credential: &credential,
		store:      storage,
		logger:     logger,
	}
	yobit.LoadCookies()
	yobit.PassCloudflare()
	yobit.SaveCookies()

	return &yobit, nil
}

func (y *Yobit) Release() {
	y.store.Release()
}

func (y *Yobit) SetCookies(cookies []*http.Cookie) {
	y.store.SaveCookies(y.site, cookies)
}

func (y *Yobit) SaveCookies() {
	cookies := y.client.Jar.Cookies(y.site)
	y.store.SaveCookies(y.site, cookies)
}

func (y *Yobit) LoadCookies() {
	cookies := y.store.LoadCookies(y.site)
	y.client.Jar.SetCookies(y.site, cookies)
}

func (y *Yobit) IsMarketExists(market string) bool {
	_, ok := y.pairs[market]
	return ok
}

func (y *Yobit) fee(market string) float64 {
	return y.pairs[market].Fee
}

func (y *Yobit) PassCloudflare() {
	channel := make(chan InfoResponse)
	errChannel := make(chan error)
	go y.Info(channel, errChannel)
	<-channel
}

// PUBLIC API ===============================

func (y *Yobit) Tickers24(pairs []string, ch chan<- TickerInfoResponse, errCh chan<- error) {
	if len(pairs) == 0 {
		errCh <- errTicketEmpty
		return
	}
	pairsLine := strings.Join(pairs, "-")
	start := time.Now()
	ticker24Url := apiBase + ApiVersion + "/ticker/" + pairsLine
	response, err := y.callPublic(ticker24Url)
	if err != nil {
		errCh <- err
		return
	}

	var tickerResponse TickerInfoResponse
	pTicker := &tickerResponse.Tickers

	if err := unmarshal(response, pTicker); err != nil {
		errCh <- err
		return
	}
	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.Tickers24 took %s", elapsed)
	}
	ch <- tickerResponse
}

func (y *Yobit) Info(ch chan<- InfoResponse, errCh chan<- error) {
	start := time.Now()
	infoUrl := apiBase + ApiVersion + "/info"
	response, err := y.callPublic(infoUrl)
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.Info took %s", elapsed)
	}

	var infoResponse InfoResponse
	if err := unmarshal(response, &infoResponse); err != nil {
		errCh <- err
		return
	}
	// cache all markets
	y.pairs = infoResponse.Pairs

	ch <- infoResponse
}

func (y *Yobit) Depth(pairs string, ch chan<- DepthResponse, errCh chan<- error) {
	y.DepthLimited(pairs, 150, ch, errCh)
}

func (y *Yobit) DepthLimited(pairs string, limit int, ch chan<- DepthResponse, errCh chan<- error) {
	start := time.Now()
	limitedDepthUrl := fmt.Sprintf("%s/depth/%s?limit=%d", apiBase+ApiVersion, pairs, limit)
	response, err := y.callPublic(limitedDepthUrl)
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.Depth took %s", elapsed)
	}
	var depthResponse DepthResponse
	if err := unmarshal(response, &depthResponse.Offers); err != nil {
		errCh <- err
		return
	}
	ch <- depthResponse
}

func (y *Yobit) TradesLimited(pairs string, limit int, ch chan<- TradesResponse, errCh chan<- error) {
	start := time.Now()
	tradesLimitedUrl := fmt.Sprintf("%s/trades/%s?limit=%d", apiBase+ApiVersion, pairs, limit)
	response, err := y.callPublic(tradesLimitedUrl)
	if err != nil {
		errCh <- err
		return
	}

	var tradesResponse TradesResponse
	if err := unmarshal(response, &tradesResponse.Trades); err != nil {
		errCh <- err
		return
	}
	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.Trades took %s", elapsed)
	}
	ch <- tradesResponse
}

// PRIVATE TRADE API =================================================================================

func (y *Yobit) GetInfo(ch chan<- GetInfoResponse, errCh chan<- error) {
	start := time.Now()
	response, err := y.callPrivate("getInfo")
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.GetInfo took %s", elapsed)
	}
	var getInfoResp GetInfoResponse
	if err := unmarshal(response, &getInfoResp); err != nil {
		errCh <- err
		return
	}
	if getInfoResp.Success == 0 {
		errCh <- errors.New(getInfoResp.Error)
	}
	ch <- getInfoResp
}

func (y *Yobit) ActiveOrders(pair string, ch chan<- ActiveOrdersResponse, errCh chan<- error) {
	start := time.Now()
	response, err := y.callPrivate("ActiveOrders", CallArg{"pair", pair})
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.ActiveOrders took %s", elapsed)
	}
	var activeOrders ActiveOrdersResponse
	if err := unmarshal(response, &activeOrders); err != nil {
		errCh <- err
		return
	}
	if activeOrders.Success == 0 {
		errCh <- errors.New(activeOrders.Error)
		return
	}
	ch <- activeOrders
}

func (y *Yobit) OrderInfo(orderId string, ch chan<- OrderInfoResponse, errCh chan<- error) {
	start := time.Now()
	response, err := y.callPrivate("OrderInfo", CallArg{"order_id", orderId})
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.OrderInfo took %s", elapsed)
	}
	var orderInfo OrderInfoResponse
	if err := unmarshal(response, &orderInfo); err != nil {
		errCh <- err
		return
	}
	if orderInfo.Success == 0 {
		errCh <- errors.New(orderInfo.Error)
		return
	}
	ch <- orderInfo
}

func (y *Yobit) Trade(pair string, tradeType string, rate float64, amount float64, ch chan TradeResponse, errCh chan<- error) {
	start := time.Now()
	response, err := y.callPrivate("Trade",
		CallArg{"pair", pair},
		CallArg{"type", tradeType},
		CallArg{"rate", strconv.FormatFloat(rate, 'f', 8, 64)},
		CallArg{"amount", strconv.FormatFloat(amount, 'f', 8, 64)},
	)
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.Trade took %s", elapsed)
	}
	var tradeResponse TradeResponse
	if err := unmarshal(response, &tradeResponse); err != nil {
		errCh <- err
		return
	}
	if tradeResponse.Success == 0 {
		errCh <- errors.New(tradeResponse.Error)
		return
	}
	ch <- tradeResponse
}

func (y *Yobit) CancelOrder(orderId string, ch chan CancelOrderResponse, errCh chan<- error) {
	start := time.Now()
	response, err := y.callPrivate("CancelOrder", CallArg{"order_id", orderId})
	if err != nil {
		errCh <- err
		return
	}

	if y.logger {
		elapsed := time.Since(start)
		log.Printf("Yobit.CancelOrder took %s", elapsed)
	}
	var cancelResponse CancelOrderResponse
	if err := unmarshal(response, &cancelResponse); err != nil {
		errCh <- err
		return
	}
	if cancelResponse.Success == 0 {
		errCh <- errors.New(cancelResponse.Error)
		return
	}
	ch <- cancelResponse
}

func (y *Yobit) TradeHistory(pair string, ch chan<- TradeHistoryResponse, errCh chan<- error) {
	response, err := y.callPrivate("TradeHistory",
		CallArg{"pair", pair},
		CallArg{"count", "1000"},
	)
	if err != nil {
		errCh <- err
		return
	}

	var tradeHistory TradeHistoryResponse
	if err := unmarshal(response, &tradeHistory); err != nil {
		errCh <- err
		return
	}
	if tradeHistory.Success == 0 {
		errCh <- errors.New(tradeHistory.Error)
		return
	}
	ch <- tradeHistory
}

func unmarshal(data []byte, obj interface{}) error {
	err := json.Unmarshal(data, obj)
	if err != nil {
		err = fmt.Errorf("unmarshaling failed. %s %s", string(data), err)
		// try to unmarshal to error response
		var errorResponse ErrorResponse
		err2 := json.Unmarshal(data, &errorResponse)
		if err2 == nil {
			err = fmt.Errorf("%s", errorResponse.Error)
		}
	}
	return err
}

func (y *Yobit) query(req *http.Request) (response []byte, err error) {
	resp, err := y.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s\nSomething goes wrong. HTTP%d", req.URL.String(), resp.StatusCode)
	}
	response, err = ioutil.ReadAll(resp.Body)
	return
}

func (y *Yobit) callPublic(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return y.query(req)
}

type CallArg struct {
	name, value string
}

func (y *Yobit) callPrivate(method string, args ...CallArg) ([]byte, error) {
	nonce, err := y.GetAndIncrementNonce()
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"method": {method},
		"nonce":  {strconv.FormatUint(nonce, 10)},
	}
	for _, arg := range args {
		form.Add(arg.name, arg.value)
	}
	encode := form.Encode()
	signature := signHmacSha512([]byte(y.credential.Secret), []byte(encode))
	body := bytes.NewBufferString(encode)
	req, err := http.NewRequest("POST", apiTrade, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-type", "application/x-www-form-urlencoded")
	req.Header.Add("Key", y.credential.Key)
	req.Header.Add("Sign", signature)

	return y.query(req)
}
