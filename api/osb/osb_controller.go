/*
 * Copyright 2018 The Service Manager Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package osb

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"

	"github.com/sirupsen/logrus"

	"github.com/Peripli/service-manager/pkg/log"
	"github.com/Peripli/service-manager/pkg/types"
	"github.com/Peripli/service-manager/pkg/util"
	"github.com/Peripli/service-manager/pkg/web"
)

var osbPathPattern = regexp.MustCompile("^" + web.OSBURL + "/[^/]+(/.*)$")

// BrokerFetcherFunc is implemented by OSB proxy providers
type BrokerFetcherFunc func(ctx context.Context, brokerID string) (*types.ServiceBroker, error)

// Controller implements api.Controller by providing OSB API logic
type Controller struct {
	BrokerFetcher BrokerFetcherFunc
}

var _ web.Controller = &Controller{}

func (c *Controller) proxyHandler(r *web.Request) (*web.Response, error) {
	return c.handler(r, c.proxy)
}

func (c *Controller) catalogHandler(r *web.Request) (*web.Response, error) {
	return c.handler(r, c.catalog)
}

func (c *Controller) handler(request *web.Request, f func(r *web.Request, logger *logrus.Entry, broker *types.ServiceBroker) (*web.Response, error)) (*web.Response, error) {
	ctx := request.Context()
	logger := log.C(ctx)
	logger.Debug("Executing OSB operation: ", request.URL.Path)
	brokerID, ok := request.PathParams[BrokerIDPathParam]
	if !ok {
		logger.Debugf("error creating OSB client: brokerID path parameter not found")
		return nil, &util.HTTPError{
			ErrorType:   "BadRequest",
			Description: "invalid broker id path parameter",
			StatusCode:  http.StatusBadRequest,
		}
	}
	logger.Debugf("Obtained path parameter [brokerID = %s] from path params", brokerID)

	broker, err := c.BrokerFetcher(ctx, brokerID)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Fetched broker %s with id %s accessible at %s", broker.ID, broker.Name, broker.BrokerURL)

	response, err := f(request, logger, broker)
	if err != nil {
		logger.WithError(err).Errorf("error proxying call to service broker with id %s", brokerID)
		return nil, &util.HTTPError{
			ErrorType:   "ServiceBrokerErr",
			Description: fmt.Sprintf("could not reach service broker with id %s", brokerID),
			StatusCode:  http.StatusBadGateway,
		}
	}
	return response, nil
}

func (c *Controller) catalog(r *web.Request, logger *logrus.Entry, broker *types.ServiceBroker) (*web.Response, error) {
	if len(broker.Catalog) == 0 {
		logger.Debugf("Fetching catalog for broker with id %s from service broker catalog endpoint", broker.ID)
		return c.proxy(r, logger, broker)
	}

	return util.NewJSONResponse(http.StatusOK, &broker.Catalog)
}

func (c *Controller) proxy(r *web.Request, logger *logrus.Entry, broker *types.ServiceBroker) (*web.Response, error) {
	ctx := r.Context()

	targetBrokerURL, _ := url.Parse(broker.BrokerURL)

	m := osbPathPattern.FindStringSubmatch(r.URL.Path)
	if m == nil || len(m) < 2 {
		return nil, fmt.Errorf("could not get OSB path from URL %s", r.URL)
	}

	modifiedRequest := r.Request.WithContext(ctx)
	modifiedRequest.SetBasicAuth(broker.Credentials.Basic.Username, broker.Credentials.Basic.Password)
	modifiedRequest.Body = ioutil.NopCloser(bytes.NewReader(r.Body))
	modifiedRequest.ContentLength = int64(len(r.Body))
	modifiedRequest.URL.Path = m[1]

	// This is needed because the request is shallow copy of the request to the Service Manager
	// This sets the host header to point to the service broker that the request will be proxied to
	modifiedRequest.Host = targetBrokerURL.Host

	proxy := buildProxy(targetBrokerURL, logger, broker)

	recorder := httptest.NewRecorder()

	proxy.ServeHTTP(recorder, modifiedRequest)

	respBody, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		return nil, err
	}

	resp := &web.Response{
		StatusCode: recorder.Code,
		Header:     recorder.Header(),
		Body:       respBody,
	}
	return resp, nil
}

func buildProxy(targetBrokerURL *url.URL, logger *logrus.Entry, broker *types.ServiceBroker) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetBrokerURL)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		director(request)
		logger.Debugf("Forwarded OSB request to service broker %s at %s", broker.Name, request.URL)
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		logger.Debugf("Service broker %s replied with status %d", broker.Name, response.StatusCode)
		return nil
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, e error) {
		logger.WithError(e).Errorf("Error while forwarding request to service broker %s", broker.Name)
		util.WriteError(&util.HTTPError{
			ErrorType:   "ServiceBrokerErr",
			Description: fmt.Sprintf("could not reach service broker %s at %s", broker.Name, request.URL),
			StatusCode:  http.StatusBadGateway,
		}, writer)
	}
	return proxy
}
