package main

import (
	"fmt"
	"net"
	"os"
)

// https://tls.ulfheim.net/

func main() {
	fmt.Println("vim-go ")
	payload := "GET / HTTP/1.1\r\nHost: www.heise.de\r\nSome: hedder\r\n\r\n"
	servAddr := "heise.de:80"
	//servAddr := "heise.de:443"

	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		println("ResolveTCPAddr failed")
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		println("DailTCP failed:", err.Error())
		os.Exit(1)
	}

	_, err = conn.Write([]byte(payload))
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}

	println("write to server = ", payload)

	reply := make([]byte, 1024)

	_, err = conn.Read(reply)
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
	println("reply form server=", string(reply))
	conn.Close()
}
