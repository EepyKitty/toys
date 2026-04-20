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

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type header struct {
	name  string
	value string
}

type httpVersion struct {
	major int
	minor int
}

var http11 = httpVersion{1, 1}

type request struct {
	method  string
	uri     string
	version httpVersion
	headers []header
}

type response struct {
	version httpVersion
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
	req, err := parseRequest(reader)
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}

	resp, err := validateOpeningHandshake(req)
	if err != nil {
		log.Printf("Server error: %v", err)
		resp = response{version: http11, status: 500, reason: "Internal Server Error"}
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
		return response{}, fmt.Errorf("invalid request method: %v", client.method)
	}

	///////////////////////
	// URI check skipped //
	///////////////////////

	if client.version.major < 1 || (client.version.major == 1 && client.version.minor < 1) {
		log.Printf("invalid HTTP version: %d.%d", client.version.major, client.version.minor)
		return response{version: http11, status: 400, reason: "Bad Request"}, nil
	}

	// 2. Host
	flag := false
	for _, h := range client.headers {
		if strings.EqualFold(h.name, "Host") {
			if flag {
				log.Printf("multiple Host headers")
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			flag = true
		}
	}
	if !flag {
		log.Printf("no Host header")
		return response{version: http11, status: 400, reason: "Bad Request"}, nil
	}

	// 3. Upgrade
	flag = false
	for _, h := range client.headers {
		if strings.EqualFold(h.name, "Upgrade") {
			if flag {
				log.Printf("multiple Upgrade headers")
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			if !strings.EqualFold(h.value, "websocket") {
				log.Printf("invalid Upgrade header value: %v", h.value)
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			flag = true
		}
	}
	if !flag {
		log.Printf("no Upgrade header")
		return response{version: http11, status: 400, reason: "Bad Request"}, nil
	}

	// 4. Connection
	flag = false
	for _, h := range client.headers {
		if strings.EqualFold(h.name, "Connection") {
			if flag {
				log.Printf("multiple Connection headers")
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			flag = true
			hasUpgrade := false
			for tok := range strings.SplitSeq(h.value, ",") {
				if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") {
					hasUpgrade = true
					break
				}
			}
			if !hasUpgrade {
				log.Printf("invalid Connection header value: %v", h.value)
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
		}
	}
	if !flag {
		log.Printf("no Connection header")
		return response{version: http11, status: 400, reason: "Bad Request"}, nil
	}

	// 5. Sec-Websocket-Key
	flag = false
	accept := ""
	for _, h := range client.headers {
		if strings.EqualFold(h.name, "Sec-WebSocket-Key") {
			if flag {
				log.Printf("multiple Sec-WebSocket-Key headers")
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			key, err := base64.StdEncoding.DecodeString(h.value)
			if err != nil {
				return response{}, fmt.Errorf("base64 decode error: %w", err)
			}
			if len(key) != 16 {
				log.Printf("invalid Sec-WebSocket-Key header value: %v", h.value)
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			flag = true
			hash := sha1.Sum([]byte(h.value + wsMagic))
			accept = base64.StdEncoding.EncodeToString(hash[:])
		}
	}
	if !flag {
		log.Printf("no Sec-WebSocket-Key header")
		return response{version: http11, status: 400, reason: "Bad Request"}, nil
	}

	// 6. Sec-WebSocket-Version
	flag = false
	for _, h := range client.headers {
		if strings.EqualFold(h.name, "Sec-WebSocket-Version") {
			if flag {
				log.Printf("multiple Sec-WebSocket-Version headers")
				return response{version: http11, status: 400, reason: "Bad Request"}, nil
			}
			if h.value != "13" {
				log.Printf("invalid Sec-WebSocket-Version header value: %v", h.value)
				return response{version: http11, status: 426, reason: "Upgrade Required", headers: []header{{name: "Sec-WebSocket-Version", value: "13"}}}, nil
			}
			flag = true
		}
	}
	if !flag {
		log.Printf("no Sec-WebSocket-Version header")
		return response{version: http11, status: 400, reason: "Bad Request"}, nil
	}

	return response{
		version: http11,
		status:  101,
		reason:  "Switching Protocols",
		headers: []header{
			{"Upgrade", "websocket"},
			{"Connection", "Upgrade"},
			{"Sec-WebSocket-Accept", accept},
		},
	}, nil
}

func parseRequest(reader *bufio.Reader) (request, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return request{}, fmt.Errorf("read error: %w", err)
	}

	// Request-Line
	reqLine := strings.SplitN(line, " ", 3)
	if len(reqLine) != 3 {
		return request{}, fmt.Errorf("malformed Request-Line: %v", line)
	}
	method, uri := reqLine[0], reqLine[1]
	if !strings.HasPrefix(reqLine[2], "HTTP/") {
		return request{}, fmt.Errorf("HTTP version error: %v", reqLine[2])
	}
	versionStr := strings.TrimRight(strings.TrimPrefix(reqLine[2], "HTTP/"), "\r\n")
	majorStr, minorStr, found := strings.Cut(versionStr, ".")
	if !found {
		return request{}, fmt.Errorf("HTTP version error: %v", versionStr)
	}
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return request{}, fmt.Errorf("HTTP version error: %w", err)
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return request{}, fmt.Errorf("HTTP version error: %w", err)
	}
	version := httpVersion{major, minor}

	// Headers
	headers := make([]header, 0, 10)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return request{}, fmt.Errorf("read error: %w", err)
		}

		if line == "\r\n" {
			break
		}

		h, err := parseHeader(line)
		if err != nil {
			return request{}, err
		}
		headers = append(headers, h)
	}

	return request{method, uri, version, headers}, nil
}

func parseHeader(raw string) (header, error) {
	name, value, found := strings.Cut(raw, ":")
	if !found {
		return header{}, fmt.Errorf("malformed header: %v", raw)
	}
	value = strings.TrimSpace(value)
	return header{name, value}, nil
}

func printResponse(resp response) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/%d.%d %d %s\r\n", resp.version.major, resp.version.minor, resp.status, resp.reason)
	for _, h := range resp.headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h.name, h.value)
	}
	b.WriteString("\r\n")
	return b.String()
}
