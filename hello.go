package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
)

// https://tls.ulfheim.net/

func sendToServer(conn net.TCPConn, msgHex string) {

	var msg []byte
	payload, err := hex.DecodeString(msgHex)
	if err != nil {
		println("DecodeString failed:", err.Error())
		os.Exit(1)
	}

	_, err = conn.Write([]byte(payload))
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
	println("write to server = ", msg)
}

func readFromServer(conn net.TCPConn) []byte {
	reply := make([]byte, 1600)
	_, err := conn.Read(reply)
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
	println("reply form server=", string(reply))
	fmt.Printf("%x", reply)
	return reply
}

func connectToServer(srvAddr string) net.TCPConn {
	tcpAddr, err := net.ResolveTCPAddr("tcp", srvAddr)
	if err != nil {
		println("ResolveTCPAddr failed")
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		println("DailTCP failed:", err.Error())
		os.Exit(1)
	}
	return *conn
}

func main() {

	srvAddr := "heise.de:443"
	conn := connectToServer(srvAddr)

	//payload_http := "GET / HTTP/1.1\r\nHost: www.heise.de\r\nSome: hedder\r\n\r\n"
	clientHelloPayloadHex := "16030100a5010000a10303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000020cca8cca9c02fc030c02bc02cc013c009c014c00a009c009d002f0035c012000a010000580000001800160000136578616d706c652e756c666865696d2e6e6574000500050100000000000a000a0008001d001700180019000b00020100000d0012001004010403050105030601060302010203ff0100010000120000"
	sendToServer(conn, clientHelloPayloadHex)
	answer := readFromServer(conn)
	fmt.Printf("answer: %x", answer)

	conn.Close()
}
