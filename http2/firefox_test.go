package http2

import (
	"bytes"
	"fmt"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2/hpack"
)

func TestTransportFirefoxHPACKPerRequest(t *testing.T) {
	ct := newClientTester(t)
	ct.client = func() error {
		for _, enabled := range []bool{true, false, true} {
			req, _ := http.NewRequest("GET", "https://dummy.tld/", nil)
			req.UseFirefoxHPACK = enabled
			req.Header.Set("Cookie", "a=b; long=abcdefghijklmnopqrstuvwxyz")
			response, err := ct.tr.RoundTrip(req)
			if err != nil {
				return err
			}
			response.Body.Close()
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		decoder := hpack.NewDecoder(initialHeaderTableSize, nil)
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
			fields, err := decoder.DecodeFull(headers.HeaderBlockFragment())
			if err != nil {
				return err
			}
			cookies := 0
			for _, field := range fields {
				if field.Name == "cookie" {
					want := request != 1 && field.Value == "a=b"
					if field.Sensitive != want {
						return fmt.Errorf("request %d cookie %s never-indexed=%t, want %t", request, field.Value, field.Sensitive, want)
					}
					cookies++
				}
			}
			if cookies != 2 {
				return fmt.Errorf("got %d cookie pairs", cookies)
			}
			var response bytes.Buffer
			encoder := hpack.NewEncoder(&response)
			encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			ct.fr.WriteHeaders(HeadersFrameParam{StreamID: headers.StreamID, EndHeaders: true, EndStream: true, BlockFragment: response.Bytes()})
			request++
			if request == 3 {
				return nil
			}
		}
	}
	ct.run()
}
