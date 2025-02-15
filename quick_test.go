package quick

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jeffotoni/quick/internal/concat"
)

// To test the entire package and check the coverage you can run those commands below:
// coverage     -> go test -v -count=1 -failfast -cover -coverprofile=coverage.out ./...
// coverageHTML -> go test -v -count=1 -failfast -cover -coverprofile=coverage.out ./...; go tool cover -html=coverage.out

func TestQuick_Use(t *testing.T) {
	type fields struct {
		routes  []Route
		mws     []func(http.Handler) http.Handler
		mux     *http.ServeMux
		handler http.Handler
	}
	type args struct {
		mw func(http.Handler) http.Handler
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &Quick{
				routes:  tt.fields.routes,
				mux:     tt.fields.mux,
				handler: tt.fields.handler,
			}
			q.Use(tt.args.mw)
		})
	}
}

// cover     ->  go test -v -count=1 -cover -failfast -run ^TestQuick_Get$
// coverHTML ->  go test -v -count=1 -failfast -cover -coverprofile=coverage.out -run ^TestQuick_Get$; go tool cover -html=coverage.out
func TestQuick_Get(t *testing.T) {
	type args struct {
		route       string
		wantCode    int
		wantOut     string
		isWantedErr bool
		reqHeaders  map[string]string
	}

	type myType struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	mt := myType{}
	mt.Name = "jeff"
	mt.Age = 35

	testSuccessMockHandler := func(c *Ctx) error {
		c.Set("Content-Type", "application/json")
		return c.JSON(mt)
	}

	r := New()
	r.Get("/test", testSuccessMockHandler)
	r.Get("/tester/:p1", testSuccessMockHandler)
	r.Get("/", testSuccessMockHandler)
	r.Get("/reg/{[0-9]}", testSuccessMockHandler)

	tests := []struct {
		name string
		args args
	}{
		{
			name: "success",
			args: args{
				route:       "/test?some=1",
				wantOut:     `{"name":"jeff","age":35}`,
				wantCode:    200,
				isWantedErr: false,
			},
		},
		{
			name: "success_with_params",
			args: args{
				route:       "/tester/val1",
				wantOut:     `{"name":"jeff","age":35}`,
				wantCode:    200,
				isWantedErr: false,
			},
		},
		{
			name: "success_with_nothing",
			args: args{
				route:       "/",
				wantOut:     `{"name":"jeff","age":35}`,
				wantCode:    200,
				isWantedErr: false,
			},
		},
		{
			name: "success_with_regex",
			args: args{
				route:       "/reg/1",
				wantOut:     `{"name":"jeff","age":35}`,
				wantCode:    200,
				isWantedErr: false,
			},
		},
		{
			name: "error_not_exists_route",
			args: args{
				route:       "/tester/val1/route",
				wantOut:     `404 page not found`,
				wantCode:    404,
				isWantedErr: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			data, err := r.QuickTest("GET", tt.args.route, tt.args.reqHeaders)
			if (!tt.args.isWantedErr) && err != nil {
				t.Errorf("error: %v", err)
				return
			}

			s := strings.TrimSpace(data.BodyStr())
			if s != tt.args.wantOut {
				t.Errorf("was suppose to return %s and %s come", tt.args.wantOut, data.BodyStr())
				return
			}

			if tt.args.wantCode != data.StatusCode() {
				t.Errorf("was suppose to return %d and %d come", tt.args.wantCode, data.StatusCode())
				return
			}

			t.Logf("outputBody -> %v", data.BodyStr())
		})
	}
}

// cover     -> go test -v -count=1 -cover -failfast -run ^TestQuick_Post$
// coverHTML -> go test -v -count=1 -failfast -cover -coverprofile=coverage.out -run ^TestQuick_Post$; go tool cover -html=coverage.out
func TestQuick_Post(t *testing.T) {
	type args struct {
		route       string
		wantCode    int
		wantOut     string
		isWantedErr bool
		reqBody     []byte
		reqHeaders  map[string]string
	}

	type myType struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	type XmlData struct {
		XMLName xml.Name `xml:"data"`
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
	}

	type myXmlType struct {
		XMLName xml.Name `xml:"MyXMLType"`
		Data    XmlData  `xml:"data"`
	}

	testSuccessMockHandler := func(c *Ctx) error {
		c.Set("Content-Type", "application/json")
		b := c.Body()
		resp := concat.String(`"data":`, string(b))
		c.Status(200)
		return c.SendString(resp)
	}

	testSuccessMockHandlerString := func(c *Ctx) error {
		c.Set("Content-Type", "application/json")
		mt := new(myType)
		if err := c.BodyParser(mt); err != nil {
			t.Errorf("error: %v", err)
		}
		b, _ := json.Marshal(mt)
		resp := concat.String(`"data":`, string(b))
		c.Status(200)
		return c.String(resp)
	}

	testSuccessMockHandlerBind := func(c *Ctx) error {
		c.Set("Content-Type", "application/json")
		mt := new(myType)
		if err := c.Bind(&mt); err != nil {
			t.Errorf("error: %v", err)
		}
		b, _ := json.Marshal(mt)
		resp := concat.String(`"data":`, string(b))
		c.Status(200)
		return c.String(resp)
	}

	testSuccessMockXml := func(c *Ctx) error {
		c.Set("Content-Type", ContentTypeTextXML)
		mtx := new(myXmlType)
		if err := c.Bind(&mtx); err != nil {
			t.Errorf("error: %v", err)
		}
		return c.Status(200).XML(mtx)
	}

	r := New()
	r.Post("/test", testSuccessMockHandler)
	r.Post("/tester/:p1", testSuccessMockHandler)
	r.Post("/", testSuccessMockHandlerString)
	r.Post("/bind", testSuccessMockHandlerBind)
	r.Post("/test/xml", testSuccessMockXml)

	tests := []struct {
		name string
		args args
	}{
		{
			name: "success",
			args: args{
				route:       "/test",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff", "age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff", "age":35}`),
			},
		},
		{
			name: "success_param",
			args: args{
				route:       "/tester/some",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff", "age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff", "age":35}`),
			},
		},
		{
			name: "success_without_param",
			args: args{
				route:       "/",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff","age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff","age":35}`),
				reqHeaders:  map[string]string{"Content-Type": "application/json"},
			},
		},
		{
			name: "success_bind",
			args: args{
				route:       "/bind",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff","age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff","age":35}`),
				reqHeaders:  map[string]string{"Content-Type": "application/json"},
			},
		},
		{
			name: "success_xml",
			args: args{
				route:       "/test/xml",
				wantCode:    200,
				wantOut:     `<MyXMLType><data><name>Jeff</name><age>35</age></data></MyXMLType>`,
				isWantedErr: false,
				reqBody:     []byte(`<MyXMLType><data><name>Jeff</name><age>35</age></data></MyXMLType>`),
				reqHeaders:  map[string]string{"Content-Type": ContentTypeTextXML},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := r.QuickTest("POST", tt.args.route, tt.args.reqHeaders, tt.args.reqBody)
			if (!tt.args.isWantedErr) && err != nil {
				t.Errorf("error: %v", err)
				return
			}

			s := strings.TrimSpace(data.BodyStr())
			if s != tt.args.wantOut {
				t.Errorf("was suppose to return %s and %s come", tt.args.wantOut, data.BodyStr())
				return
			}

			if tt.args.wantCode != data.StatusCode() {
				t.Errorf("was suppose to return %d and %d come", tt.args.wantCode, data.StatusCode())
				return
			}

			t.Logf("outputBody -> %v", data.BodyStr())
		})
	}
}

// cover     -> go test -v -count=1 -cover -failfast -run ^TestQuick_Put$
// coverHTML -> go test -v -count=1 -failfast -cover -coverprofile=coverage.out -run ^TestQuick_Put$; go tool cover -html=coverage.out
func TestQuick_Put(t *testing.T) {
	type args struct {
		route       string
		wantCode    int
		wantOut     string
		isWantedErr bool
		reqBody     []byte
		reqHeaders  map[string]string
	}

	testSuccessMockHandler := func(c *Ctx) error {
		c.Set("Content-Type", "application/json")
		b := c.Body()
		resp := concat.String(`"data":`, string(b))
		c.Byte([]byte(resp))
		return nil
	}

	r := New()
	r.Put("/", testSuccessMockHandler)
	r.Put("/test", testSuccessMockHandler)
	r.Put("/tester/:p1", testSuccessMockHandler)
	r.Put("/jeff", testSuccessMockHandler)

	tests := []struct {
		name string
		args args
	}{
		{
			name: "success",
			args: args{
				route:       "/test",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff", "age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff", "age":35}`),
			},
		},
		{
			name: "success_param",
			args: args{
				route:       "/tester/:p1",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff", "age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff", "age":35}`),
			},
		},
		{
			name: "success_without_param",
			args: args{
				route:       "/",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff", "age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff", "age":35}`),
				reqHeaders:  map[string]string{"Content-Type": "application/json"},
			},
		},
		{
			name: "success_without_param",
			args: args{
				route:       "/jeff",
				wantCode:    200,
				wantOut:     `"data":{"name":"jeff", "age":35}`,
				isWantedErr: false,
				reqBody:     []byte(`{"name":"jeff", "age":35}`),
				reqHeaders:  map[string]string{"Content-Type": "application/json"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := r.QuickTest("PUT", tt.args.route, tt.args.reqHeaders, tt.args.reqBody)
			if (!tt.args.isWantedErr) && err != nil {
				t.Errorf("error: %v", err)
				return
			}

			s := strings.TrimSpace(data.BodyStr())
			if s != tt.args.wantOut {
				t.Errorf("route %s -> was suppose to return %s and %s come", tt.args.route, tt.args.wantOut, data.BodyStr())
				return
			}

			if tt.args.wantCode != data.StatusCode() {
				t.Errorf("was suppose to return %d and %d come", tt.args.wantCode, data.StatusCode())
				return
			}

			t.Logf("\nOutputBodyString -> %v", data.BodyStr())
			t.Logf("\nStatusCode -> %d", data.StatusCode())
			t.Logf("\nOutputBody -> %v", string(data.Body())) // I have converted in this example to string but comes []byte as default
			t.Logf("\nResponse -> %v", data.Response())
		})
	}
}

func Test_extractParamsPost(t *testing.T) {
	type args struct {
		quick       Quick
		pathTmp     string
		handlerFunc func(*Ctx) error
	}
	tests := []struct {
		name string
		args args
		want http.HandlerFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractParamsPost(&tt.args.quick, tt.args.pathTmp, tt.args.handlerFunc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractParamsPost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCtx_Param(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		key string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if got := c.Param(tt.args.key); got != tt.want {
				t.Errorf("Ctx.Param() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCtx_Body(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		v interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if err := c.BodyParser(tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("Ctx.Body() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCtx_BodyString(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if got := c.BodyString(); got != tt.want {
				t.Errorf("Ctx.BodyString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuick_ServeStaticFile(t *testing.T) {
	type fields struct {
		routes  []Route
		mws     []func(http.Handler) http.Handler
		mux     *http.ServeMux
		handler http.Handler
	}
	type args struct {
		pattern     string
		handlerFunc func(*Ctx) error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Quick{
				routes: tt.fields.routes,

				mux:     tt.fields.mux,
				handler: tt.fields.handler,
			}
			r.Get(tt.args.pattern, tt.args.handlerFunc)
		})
	}
}

func Test_extractParamsGet(t *testing.T) {
	type args struct {
		pathTmp     string
		paramsPath  string
		handlerFunc func(*Ctx) error
	}
	tests := []struct {
		name string
		args args
		want http.HandlerFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractParamsGet(tt.args.pathTmp, tt.args.paramsPath, tt.args.handlerFunc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractParamsGet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuick_ServeHTTP(t *testing.T) {
	type fields struct {
		routes  []Route
		mws     []func(http.Handler) http.Handler
		mux     *http.ServeMux
		handler http.Handler
	}
	type args struct {
		w   http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &Quick{
				routes: tt.fields.routes,

				mux:     tt.fields.mux,
				handler: tt.fields.handler,
			}
			q.ServeHTTP(tt.args.w, tt.args.req)
		})
	}
}

func TestCtx_Json(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		v interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if err := c.JSON(tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("Ctx.Json() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCtx_Byte(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if err := c.Byte(tt.args.b); (err != nil) != tt.wantErr {
				t.Errorf("Ctx.Byte() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCtx_SendString(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if err := c.SendString(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("Ctx.SendString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCtx_Set(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			c.Set(tt.args.key, tt.args.value)
		})
	}
}

func TestCtx_Accepts(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		acceptType string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Ctx
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if got := c.Accepts(tt.args.acceptType); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Ctx.Accepts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCtx_Status(t *testing.T) {
	type fields struct {
		Response http.ResponseWriter
		Request  *http.Request
		Headers  map[string][]string
		Params   map[string]string
		Query    map[string]string
		JSON     map[string]interface{}
		BodyByte []byte
		JsonStr  string
	}
	type args struct {
		status int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Ctx
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response: tt.fields.Response,
				Request:  tt.fields.Request,
				Headers:  tt.fields.Headers,
				Params:   tt.fields.Params,
				Query:    tt.fields.Query,
				//JSON:     tt.fields.JSON,
				bodyByte: tt.fields.BodyByte,
				JsonStr:  tt.fields.JsonStr,
			}
			if got := c.Status(tt.args.status); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Ctx.Status() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuick_GetRoute(t *testing.T) {
	type fields struct {
		routes  []Route
		mws     []func(http.Handler) http.Handler
		mux     *http.ServeMux
		handler http.Handler
	}
	tests := []struct {
		name   string
		fields fields
		want   []Route
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Quick{
				routes: tt.fields.routes,

				mux:     tt.fields.mux,
				handler: tt.fields.handler,
			}
			if got := r.GetRoute(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Quick.GetRoute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuick_Listen(t *testing.T) {
	type fields struct {
		routes  []Route
		mws     []func(http.Handler) http.Handler
		mux     *http.ServeMux
		handler http.Handler
	}
	type args struct {
		addr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &Quick{
				routes: tt.fields.routes,

				mux:     tt.fields.mux,
				handler: tt.fields.handler,
			}
			if err := q.Listen(tt.args.addr); (err != nil) != tt.wantErr {
				t.Errorf("Quick.Listen() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func benchmarkWriteToStdout(b *testing.B, size int) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		os.Stdout.Write(make([]byte, size))
	}
}

func benchmarkPrintln(b *testing.B, size int) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fmt.Println(make([]byte, size))
	}
}

func BenchmarkWriteToStdout_10Bytes(b *testing.B) {
	benchmarkWriteToStdout(b, 10)
}

func BenchmarkPrintln_10Bytes(b *testing.B) {
	benchmarkPrintln(b, 10)
}

func BenchmarkWriteToStdout_100Bytes(b *testing.B) {
	benchmarkWriteToStdout(b, 100)
}

func BenchmarkPrintln_100Bytes(b *testing.B) {
	benchmarkPrintln(b, 100)
}

func BenchmarkWriteToStdout_1000Bytes(b *testing.B) {
	benchmarkWriteToStdout(b, 1000)
}

func BenchmarkPrintln_1000Bytes(b *testing.B) {
	benchmarkPrintln(b, 1000)
}

// go test -v -count=1 -failfast -run ^Test_extractParamsPattern$
func Test_extractParamsPattern(t *testing.T) {
	type args struct {
		pattern string
	}
	tests := []struct {
		name              string
		args              args
		wantPath          string
		wantParams        string
		wantPartternExist string
	}{
		{
			name: "should ble able to extract 1 param",
			args: args{
				pattern: "/v1/customer/:param1",
			},
			wantPath:          "/v1/customer",
			wantParams:        "/:param1",
			wantPartternExist: "/v1/customer/:param1",
		},
		{
			name: "should ble able to extract 2 params",
			args: args{
				pattern: "/v1/customer/params/:param1/:param2",
			},
			wantPath:          "/v1/customer/params",
			wantParams:        "/:param1/:param2",
			wantPartternExist: "/v1/customer/params/:param1/:param2",
		},
		{
			name: "should ble able to extract 3 params",
			args: args{
				pattern: "/v1/customer/params/:param1/:param2/some/:param3",
			},
			wantPath:          "/v1/customer/params",
			wantParams:        "/:param1/:param2/some/:param3",
			wantPartternExist: "/v1/customer/params/:param1/:param2/some/:param3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotParams, gotPartternExist := extractParamsPattern(tt.args.pattern)
			if gotPath != tt.wantPath {
				t.Errorf("extractParamsPattern() gotPath = %v, want %v", gotPath, tt.wantPath)
			}
			if gotParams != tt.wantParams {
				t.Errorf("extractParamsPattern() gotParams = %v, want %v", gotParams, tt.wantParams)
			}
			if gotPartternExist != tt.wantPartternExist {
				t.Errorf("extractParamsPattern() gotPartternExist = %v, want %v", gotPartternExist, tt.wantPartternExist)
			}
		})
	}
}

func TestCtx_Append(t *testing.T) {
	type fields struct {
		Response  http.ResponseWriter
		Request   *http.Request
		resStatus int
		bodyByte  []byte
		JsonStr   string
		Headers   map[string][]string
		Params    map[string]string
		Query     map[string]string
	}
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantLen int
	}{
		{
			name: "should be able to create a new header",
			fields: fields{
				Response: httptest.NewRecorder(),
			},
			args: args{
				key:   "Append",
				value: "one",
			},
			wantLen: 1,
		},
		{
			name: "should be able to append to existing header",
			fields: fields{
				Response: func() http.ResponseWriter { x := httptest.NewRecorder(); x.Header().Set("Append", "one"); return x }(),
			},
			args: args{
				key:   "Append",
				value: "two",
			},
			wantLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ctx{
				Response:  tt.fields.Response,
				Request:   tt.fields.Request,
				resStatus: tt.fields.resStatus,
				bodyByte:  tt.fields.bodyByte,
				JsonStr:   tt.fields.JsonStr,
				Headers:   tt.fields.Headers,
				Params:    tt.fields.Params,
				Query:     tt.fields.Query,
			}
			c.Append(tt.args.key, tt.args.value)

			if len(c.Response.Header().Values(tt.args.key)) != tt.wantLen {
				t.Errorf("c.Append(): want %v, got %v", tt.wantLen, len(c.Response.Header().Values(tt.args.key)))
			}
		})
	}
}
