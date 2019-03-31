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
	"os"
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

type Yobit struct {
	site       *url.URL
	client     *http.Client
	credential *ApiCredential
	pairs      map[string]PairInfo
	mutex      sync.Mutex
	store      *LocalStorage
	logger     bool
}

func fatal(v ...interface{}) {
	fmt.Printf("%s\n", fmt.Sprint(v))
	os.Exit(1)
}

func New(credential ApiCredential, logger bool) *Yobit {
	cloudflare, err := scraper.NewTransport(http.DefaultTransport)
	if err != nil {
		fatal(err)
	}

	yobitUrl, _ := url.Parse(Url)

	yobit := Yobit{
		site:       yobitUrl,
		client:     &http.Client{Transport: cloudflare, Jar: cloudflare.Cookies, Timeout: time.Second * 10},
		credential: &credential,
		store:      NewStorage(),
		logger:     logger,
	}
	yobit.LoadCookies()
	yobit.PassCloudflare()
	yobit.SaveCookies()

	return &yobit
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
	go y.Info(channel)
	<-channel
}

// PUBLIC API ===============================

func (y *Yobit) Tickers24(pairs []string, ch chan<- TickerInfoResponse) {
	if len(pairs) == 0 {
		fatal("Tickers24: Tickers list is empty")
	}
	pairsLine := strings.Join(pairs, "-")
	start := time.Now()
	ticker24Url := apiBase + ApiVersion + "/ticker/" + pairsLine
	response := y.callPublic(ticker24Url)

	var tickerResponse TickerInfoResponse
	pTicker := &tickerResponse.Tickers

	if err := unmarshal(response, pTicker); err != nil {
		fatal(err)
	}
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.Tickers24 took %s", elapsed)
	}
	ch <- tickerResponse
}

func (y *Yobit) Info(ch chan<- InfoResponse) {
	start := time.Now()
	infoUrl := apiBase + ApiVersion + "/info"
	response := y.callPublic(infoUrl)
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.Info took %s", elapsed)
	}

	var infoResponse InfoResponse
	if err := unmarshal(response, &infoResponse); err != nil {
		fatal(err)
	}
	// cache all markets
	y.pairs = infoResponse.Pairs

	ch <- infoResponse
}

func (y *Yobit) Depth(pairs string, ch chan<- DepthResponse) {
	y.DepthLimited(pairs, 150, ch)
}

func (y *Yobit) DepthLimited(pairs string, limit int, ch chan<- DepthResponse) {
	start := time.Now()
	limitedDepthUrl := fmt.Sprintf("%s/depth/%s?limit=%d", apiBase+ApiVersion, pairs, limit)
	response := y.callPublic(limitedDepthUrl)
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.Depth took %s", elapsed)
	}
	var depthResponse DepthResponse
	if err := unmarshal(response, &depthResponse.Offers); err != nil {
		fatal(err)
	}
	ch <- depthResponse
}

func (y *Yobit) TradesLimited(pairs string, limit int, ch chan<- TradesResponse) {
	start := time.Now()
	tradesLimitedUrl := fmt.Sprintf("%s/trades/%s?limit=%d", apiBase+ApiVersion, pairs, limit)
	response := y.callPublic(tradesLimitedUrl)
	var tradesResponse TradesResponse
	if err := unmarshal(response, &tradesResponse.Trades); err != nil {
		fatal(err)
	}
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.Trades took %s", elapsed)
	}
	ch <- tradesResponse
}

// PRIVATE TRADE API =================================================================================

func (y *Yobit) GetInfo(ch chan<- GetInfoResponse) {
	start := time.Now()
	response := y.callPrivate("getInfo")
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.GetInfo took %s", elapsed)
	}
	var getInfoResp GetInfoResponse
	if err := unmarshal(response, &getInfoResp); err != nil {
		fatal(err)
	}
	if getInfoResp.Success == 0 {
		fatal(errors.New(getInfoResp.Error))
	}
	ch <- getInfoResp
}

func (y *Yobit) ActiveOrders(pair string, ch chan<- ActiveOrdersResponse) {
	start := time.Now()
	response := y.callPrivate("ActiveOrders", CallArg{"pair", pair})
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.ActiveOrders took %s", elapsed)
	}
	var activeOrders ActiveOrdersResponse
	if err := unmarshal(response, &activeOrders); err != nil {
		fatal(err)
	}
	if activeOrders.Success == 0 {
		fatal(errors.New(activeOrders.Error))
	}
	ch <- activeOrders
}

func (y *Yobit) OrderInfo(orderId string, ch chan<- OrderInfoResponse) {
	start := time.Now()
	response := y.callPrivate("OrderInfo", CallArg{"order_id", orderId})
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.OrderInfo took %s", elapsed)
	}
	var orderInfo OrderInfoResponse
	if err := unmarshal(response, &orderInfo); err != nil {
		fatal(err)
	}
	if orderInfo.Success == 0 {
		fatal(errors.New(orderInfo.Error))
	}
	ch <- orderInfo
}

func (y *Yobit) Trade(pair string, tradeType string, rate float64, amount float64) (*TradeResponse, error) {
	start := time.Now()
	response := y.callPrivate("Trade",
		CallArg{"pair", pair},
		CallArg{"type", tradeType},
		CallArg{"rate", strconv.FormatFloat(rate, 'f', 8, 64)},
		CallArg{"amount", strconv.FormatFloat(amount, 'f', 8, 64)},
	)
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.Trade took %s", elapsed)
	}
	var tradeResponse *TradeResponse
	if err := unmarshal(response, &tradeResponse); err != nil {
		return nil, err
	}
	if tradeResponse.Success == 0 {
		return nil, errors.New(tradeResponse.Error)
	}
	return tradeResponse, nil
}

func (y *Yobit) CancelOrder(orderId string, ch chan CancelOrderResponse) {
	start := time.Now()
	response := y.callPrivate("CancelOrder", CallArg{"order_id", orderId})
	elapsed := time.Since(start)
	if y.logger {
		log.Printf("Yobit.CancelOrder took %s", elapsed)
	}
	var cancelResponse CancelOrderResponse
	if err := unmarshal(response, &cancelResponse); err != nil {
		fatal(err)
	}
	if cancelResponse.Success == 0 {
		fatal(errors.New(cancelResponse.Error))
	}
	ch <- cancelResponse
}

func (y *Yobit) TradeHistory(pair string, ch chan<- TradeHistoryResponse) {
	response := y.callPrivate("TradeHistory",
		CallArg{"pair", pair},
		CallArg{"count", "1000"},
	)
	var tradeHistory TradeHistoryResponse
	if err := unmarshal(response, &tradeHistory); err != nil {
		fatal(err)
	}
	if tradeHistory.Success == 0 {
		fatal(errors.New(tradeHistory.Error))
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

func (y *Yobit) query(req *http.Request) []byte {
	resp, err := y.client.Do(req)
	if err != nil {
		fatal("Do: ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fatal(fmt.Errorf("%s\nSomething goes wrong. HTTP%d", req.URL.String(), resp.StatusCode))
	}
	response, _ := ioutil.ReadAll(resp.Body)
	return response
}

func (y *Yobit) callPublic(url string) []byte {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fatal("NewRequest: ", err)
	}
	return y.query(req)
}

type CallArg struct {
	name, value string
}

func (y *Yobit) callPrivate(method string, args ...CallArg) []byte {
	nonce := y.GetAndIncrementNonce()
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
		fatal(err)
	}

	req.Header.Add("Content-type", "application/x-www-form-urlencoded")
	req.Header.Add("Key", y.credential.Key)
	req.Header.Add("Sign", signature)

	query := y.query(req)
	return query
}
