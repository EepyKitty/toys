package main

import (
	"bufio"
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
	version float32
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

	response := fmt.Sprintf("ACK: %+v\n", request)
	_, err = conn.Write([]byte(response))
	if err != nil {
		log.Printf("Server write error: %v", err)
	}
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
	if version < 1.1 {
		log.Printf("Invalid HTTP Version: %.1f", version)
		return request{}, fmt.Errorf("Invalid HTTP Version: %.1f", version)
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
