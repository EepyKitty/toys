package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

type header struct {
	name  string
	value string
}

type request struct {
	method  string
	uri     string
	version float32 // TODO: Change this to major . minor (2 ints)
	headers []header
}

type response struct {
	version float32 // TODO: Change this to major . minor (2 ints)
	status  int
	reason  string
	headers []header
}

func main() {

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("Error listening:", err)
	}

	defer listener.Close()

	for {

		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting conn:", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {

	defer conn.Close()

	reader := bufio.NewReader(conn)
	request, err := parseRequest(reader)
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}

	resp, err := validateOpeningHandshake(request)
	if err != nil {
		log.Printf("Server error: %v", err)
		resp = response{version: 1.1, status: 500, reason: "Internal Server Error"}
	}
	_, err = conn.Write([]byte(printResponse(resp)))
	if err != nil {
		log.Printf("Server write error: %v", err)
	}
}

func validateOpeningHandshake(client request) (response, error) {
	// https://datatracker.ietf.org/doc/html/rfc6455#section-4.2.1
	// https://datatracker.ietf.org/doc/html/rfc6455#section-4.2.2
	// 1. Request-Line
	if client.method != "GET" {
		log.Printf("Invalid Request Method: %v", client.method)
		return response{}, fmt.Errorf("Invalid Request Method: %v", client.method)
	}

	///////////////////////
	// URI check skipped //
	///////////////////////

	if client.version < 1.1 {
		log.Printf("Invalid HTTP Version: %.1f", client.version)
		return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
	}

	// 2. Host
	flag := false
	for _, header := range client.headers {
		{
			if strings.EqualFold(header.name, "Host") {
				if flag {
					log.Printf("Multiple Host headers")
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				flag = true
			}
		}
	}
	if !flag {
		log.Printf("No Host header")
		return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
	}

	// 3. Upgrade
	flag = false
	for _, head := range client.headers {
		{
			if strings.EqualFold(head.name, "Upgrade") {
				if flag {
					log.Printf("Multiple Upgrade headers")
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				if !strings.EqualFold(head.value, "websocket") {
					log.Printf("Invalid Upgrade header value: %v", head.value)
					return response{version: 1.1, status: 426, reason: "Upgrade Required", headers: []header{header{name: "Sec-WebSocket-Version", value: "13"}}}, nil
				}
				flag = true
			}
		}
	}
	if !flag {
		log.Printf("No Upgrade header")
		return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
	}

	// 4. Connection
	flag = false
	for _, header := range client.headers {
		{
			if strings.EqualFold(header.name, "Connection") {
				if flag {
					log.Printf("Multiple Connection headers")
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				if !strings.EqualFold(header.value, "Upgrade") {
					log.Printf("Invalid Connection header value: %v", header.value)
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				flag = true
			}
		}
	}
	if !flag {
		log.Printf("No Connection header")
		return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
	}

	// 5. Sec-Websocket-Key
	flag = false
	accept := ""
	for _, header := range client.headers {
		{
			if strings.EqualFold(header.name, "Sec-WebSocket-Key") {
				if flag {
					log.Printf("Multiple Sec-WebSocket-Key headers")
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				key, err := base64.StdEncoding.DecodeString(header.value)
				if err != nil {
					log.Printf("Base64 Decryption Error: %v", err)
					return response{}, err
				}
				if len(key) != 16 {
					log.Printf("Invalid Sec-WebSocket-Key header value: %v", header.value)
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				flag = true
				const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
				hash := sha1.Sum([]byte(header.value + magic))
				accept = base64.StdEncoding.EncodeToString(hash[:])
			}
		}
	}
	if !flag {
		log.Printf("No Sec-WebSocket-Key header")
		return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
	}

	// 6. Sec-WebSocket-Version
	flag = false
	for _, header := range client.headers {
		{
			if strings.EqualFold(header.name, "Sec-WebSocket-Version") {
				if flag {
					log.Printf("Multiple Sec-WebSocket-Version headers")
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				if !strings.EqualFold(header.value, "13") {
					log.Printf("Invalid Sec-WebSocket-Version header value: %v", header.value)
					return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
				}
				flag = true
			}
		}
	}
	if !flag {
		log.Printf("No Sec-WebSocket-Version header")
		return response{version: 1.1, status: 400, reason: "Bad Request"}, nil
	}

	return response{
		version: 1.1,
		status:  101,
		reason:  "Switching Protocols",
		headers: []header{
			{"Upgrade", "websocket"},
			{"Connection", "Upgrade"},
			{"Sec-WebSocket-Accept", accept}}}, nil
}

func parseRequest(reader *bufio.Reader) (request, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Read error: %v", err)
		return request{}, err
	}

	// Request-Line
	reqLine := strings.Split(line, " ")
	if len(reqLine) != 3 {
		log.Printf("Malformed Request-Line: %v", line)
		return request{}, fmt.Errorf("Malformed Request-Line")
	}
	method, uri := reqLine[0], reqLine[1]
	if !strings.HasPrefix(reqLine[2], "HTTP/") {
		log.Printf("HTTP Version error: %v", reqLine[2])
		return request{}, fmt.Errorf("HTTP Version error: %v", reqLine[2])
	}
	version, err := strconv.ParseFloat(strings.TrimSpace(reqLine[2][5:]), 32)
	if err != nil {
		log.Printf("HTTP Version error: %v", err)
		return request{}, err
	}

	// Headers
	headers := make([]header, 0, 10)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Read error: %v", err)
			return request{}, err
		}

		if line == "\r\n" {
			break
		}

		header, err := parseHeader(line)
		if err != nil {
			return request{}, err
		}
		headers = append(headers, header)
	}

	return request{method, uri, float32(version), headers}, nil
}

func parseHeader(raw string) (header, error) {
	name, value, found := strings.Cut(raw, ":")
	if !found {
		log.Printf("Malformed header: %v", raw)
		return header{}, fmt.Errorf("Malformed header input")
	}
	value = strings.TrimSpace(value)
	return header{name, value}, nil
}

func printResponse(resp response) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/%.1f %d %s\r\n", resp.version, resp.status, resp.reason)
	for _, h := range resp.headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h.name, h.value)
	}
	b.WriteString("\r\n")
	return b.String()
}
