package quickCtx

import "net/http"

type Ctx struct {
	Response  http.ResponseWriter
	Request   *http.Request
	resStatus int
	bodyByte  []byte
	JsonStr   string
	Headers   map[string][]string
	Params    map[string]string
	Query     map[string]string
}
