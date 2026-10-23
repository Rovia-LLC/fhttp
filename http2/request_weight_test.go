package http2

import (
	"bytes"
	"fmt"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2/hpack"
)

func TestTransportRequestWeight(t *testing.T) {
	ct := newClientTester(t)
	ct.tr.HeaderPriority = &PriorityParam{Weight: 41}
	weights := []*uint8{nil, requestWeight(21), requestWeight(0), requestWeight(255), nil}
	ct.client = func() error {
		for _, weight := range weights {
			req, _ := http.NewRequest("GET", "https://dummy.tld/", nil)
			req.HTTP2Weight = weight
			response, err := ct.tr.RoundTrip(req)
			if err != nil {
				return err
			}
			response.Body.Close()
		}
		if ct.tr.HeaderPriority.Weight != 41 {
			return fmt.Errorf("request mutated profile priority")
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		request := 0
		for {
			frame, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}
			headers, ok := frame.(*HeadersFrame)
			if !ok {
				continue
			}
			want := uint8(41)
			if weights[request] != nil {
				want = *weights[request]
			}
			if headers.Priority.Weight != want || headers.Priority.StreamDep != 0 || headers.Priority.Exclusive {
				return fmt.Errorf("request %d priority %+v, want weight %d and unchanged dependency/exclusivity", request, headers.Priority, want)
			}
			var response bytes.Buffer
			encoder := hpack.NewEncoder(&response)
			encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			ct.fr.WriteHeaders(HeadersFrameParam{StreamID: headers.StreamID, EndHeaders: true, EndStream: true, BlockFragment: response.Bytes()})
			request++
			if request == len(weights) {
				return nil
			}
		}
	}
	ct.run()
}

func requestWeight(value uint8) *uint8 { return &value }
