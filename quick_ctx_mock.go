package quick

import (
	"bytes"
	"errors"
	"github.com/jeffotoni/quick/context"
	"io"
	"net/http/httptest"
	"strings"
)

type (
	QuickMockCtx interface {
		Get(URI string) error
		Post(URI string, body []byte) error
		Put(URI string, body []byte) error
		Delete(URI string) error
	}

	quickMockCtxJSON struct {
		Ctx    *quickCtx.Ctx
		Params map[string]string
	}

	quickMockCtxXML struct {
		Ctx         *quickCtx.Ctx
		Params      map[string]string
		ContentType string
	}
)

func QuickMockCtxJSON(ctx *quickCtx.Ctx, params map[string]string) QuickMockCtx {
	return &quickMockCtxJSON{
		Ctx:    ctx,
		Params: params,
	}
}

func QuickMockCtxXML(ctx *Ctx, params map[string]string, contentType string) QuickMockCtx {
	return &quickMockCtxXML{
		Ctx:         ctx,
		Params:      params,
		ContentType: contentType,
	}
}

func (m quickMockCtxJSON) Get(URI string) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}
	queryMap := make(map[string]string)

	req := httptest.NewRequest("GET", URI, nil)
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", ContentTypeAppJSON)
	m.Ctx.Params = m.Params
	query := req.URL.Query()
	spltQuery := strings.Split(query.Encode(), "&")

	for i := 0; i < len(spltQuery); i++ {
		spltVal := strings.Split(spltQuery[i], "=")
		if len(spltVal) > 1 {
			queryMap[spltVal[0]] = spltVal[1]
		}
	}

	m.Ctx.Query = queryMap
	return nil
}

func (m quickMockCtxJSON) Post(URI string, body []byte) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}

	req := httptest.NewRequest("POST", URI, io.NopCloser(bytes.NewBuffer(body)))
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", ContentTypeAppJSON)
	m.Ctx.Params = m.Params
	m.Ctx.bodyByte = body
	return nil
}

func (m quickMockCtxJSON) Put(URI string, body []byte) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}

	req := httptest.NewRequest("PUT", URI, io.NopCloser(bytes.NewBuffer(body)))
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", ContentTypeAppJSON)
	m.Ctx.Params = m.Params
	m.Ctx.bodyByte = body
	return nil
}

func (m quickMockCtxJSON) Delete(URI string) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}

	req := httptest.NewRequest("DELETE", URI, nil)
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", ContentTypeAppJSON)
	m.Ctx.Params = m.Params
	return nil
}

func (m quickMockCtxXML) Get(URI string) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}
	queryMap := make(map[string]string)

	contentT := ContentTypeTextXML

	if len(m.ContentType) != 0 {
		contentT = m.ContentType
	}

	req := httptest.NewRequest("GET", URI, nil)
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", contentT)
	m.Ctx.Params = m.Params
	query := req.URL.Query()
	spltQuery := strings.Split(query.Encode(), "&")

	for i := 0; i < len(spltQuery); i++ {
		spltVal := strings.Split(spltQuery[i], "=")
		if len(spltVal) > 1 {
			queryMap[spltVal[0]] = spltVal[1]
		}
	}

	m.Ctx.Query = queryMap
	return nil
}

func (m quickMockCtxXML) Post(URI string, body []byte) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}

	contentT := ContentTypeTextXML

	if len(m.ContentType) != 0 {
		contentT = m.ContentType
	}

	req := httptest.NewRequest("POST", URI, io.NopCloser(bytes.NewBuffer(body)))
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", contentT)
	m.Ctx.Params = m.Params
	m.Ctx.bodyByte = body
	return nil
}

func (m quickMockCtxXML) Put(URI string, body []byte) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}

	contentT := ContentTypeTextXML

	if len(m.ContentType) != 0 {
		contentT = m.ContentType
	}

	req := httptest.NewRequest("PUT", URI, io.NopCloser(bytes.NewBuffer(body)))
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", contentT)
	m.Ctx.Params = m.Params
	m.Ctx.bodyByte = body
	return nil
}

func (m quickMockCtxXML) Delete(URI string) error {
	if m.Ctx == nil {
		return errors.New("ctx is null")
	}

	contentT := ContentTypeTextXML

	if len(m.ContentType) != 0 {
		contentT = m.ContentType
	}

	req := httptest.NewRequest("DELETE", URI, nil)
	m.Ctx.Request = req
	m.Ctx.Request.Header.Set("Content-Type", contentT)
	m.Ctx.Params = m.Params
	return nil
}
