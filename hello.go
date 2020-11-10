package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
)

// https://tls.ulfheim.net/

func sendToServer(conn net.TCPConn, msgHex string) {

	//var msg []byte
	fmt.Println("Sending 'Client Hello' to server:", msgHex)
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
	//println("write to server = ", msg)
}

func readFromServer(conn net.TCPConn) []byte {
	reply := make([]byte, 600)
	_, err := conn.Read(reply)
	if err != nil {
		println("Read from server failed:", err.Error())
		os.Exit(1)
	}
	//println("reply form server=", string(reply))
	fmt.Printf("Message received from server: %x\n", reply)
	return reply
}

func connectToServer(srvAddr string) net.TCPConn {
	fmt.Println("Connecting to server:", srvAddr)
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

func parseHelloServer(answer []byte) ServerHello {
	serverHello := ServerHello{}
	offset := 0
	println("Parsing Server Hello")
	//println("Parsing Server Hello > Record Header")
	recordHeader := RecordHeader{}
	recordHeader.ttype = answer[0]
	copy(recordHeader.protocol_verion[:], answer[1:3])
	copy(recordHeader.footer[:], answer[3:5])
	//println(recordHeader.footer[0], recordHeader.footer[1])
	recordHeader.footerInt = binary.BigEndian.Uint16(answer[3:5])
	serverHello.recordHeader = recordHeader

	offset += 5
	handshakeHeader := HandshakeHeader{}
	handshakeHeader.message_type = answer[offset+0]
	copy(handshakeHeader.footer[:], answer[offset+1:offset+4])
	handshakeHeader.footerInt = binary.BigEndian.Uint32(append([]byte{0}, answer[offset+1:offset+4]...))
	serverHello.handshakeHeader = handshakeHeader

	offset += 4
	copy(serverHello.serverVersion[:], answer[offset:offset+2])
	copy(serverHello.serverRandom[:], answer[offset+2:offset+34])
	copy(serverHello.sessionID[:], answer[offset+34:offset+35])
	copy(serverHello.cipherSuite[:], answer[offset+35:offset+37])
	copy(serverHello.compressionMethod[:], answer[offset+37:offset+38])
	copy(serverHello.extensionLength[:], answer[offset+38:offset+40])

	extensionRenegotiationInfo := ExtensionRenegotiationInfo{}
	offset += 40
	copy(extensionRenegotiationInfo.info[:], answer[offset:offset+2])
	copy(extensionRenegotiationInfo.length[:], answer[offset+2:offset+4])
	copy(extensionRenegotiationInfo.payload[:], answer[offset+4:offset+5])
	serverHello.extensionRenegotiationInfo = extensionRenegotiationInfo

	//copy(serverHello.extensionRenegotiationInfo[:], answer[offset+40:offset+45])

	return serverHello
}

type RecordHeader struct {
	ttype           byte
	protocol_verion [2]byte
	footer          [2]byte
	footerInt       uint16
}

type HandshakeHeader struct {
	message_type byte
	footer       [3]byte
	footerInt    uint32
}

type ExtensionRenegotiationInfo struct {
	info    [2]byte
	length  [2]byte
	payload [1]byte
}

type ServerHello struct {
	recordHeader               RecordHeader
	handshakeHeader            HandshakeHeader
	serverVersion              [2]byte
	serverRandom               [32]byte
	sessionID                  [1]byte
	cipherSuite                [2]byte
	compressionMethod          [1]byte
	extensionLength            [2]byte
	extensionRenegotiationInfo ExtensionRenegotiationInfo
}

func (serverHello ServerHello) String() string {
	out := fmt.Sprintf("Server Hello\n")
	out += fmt.Sprintf("  Record Header\n")
	out += fmt.Sprintf("    ttype...........: %x\n", serverHello.recordHeader.ttype)
	out += fmt.Sprintf("    protocol Version: %x\n", serverHello.recordHeader.protocol_verion)
	out += fmt.Sprintf("    footer..........: %x\n", serverHello.recordHeader.footer)
	out += fmt.Sprintf("    footerInt.......: %x\n", serverHello.recordHeader.footerInt)
	out += fmt.Sprintf("  Handshake Header\n")
	out += fmt.Sprintf("    message type....: %02x\n", serverHello.handshakeHeader.message_type)
	out += fmt.Sprintf("    footer..........: %x\n", serverHello.handshakeHeader.footer)
	out += fmt.Sprintf("    footerInt.......: %x\n", serverHello.handshakeHeader.footerInt)
	out += fmt.Sprintf("  Server Version....: %x\n", serverHello.serverVersion)
	out += fmt.Sprintf("  Server Random.....: %x\n", serverHello.serverRandom)
	out += fmt.Sprintf("  Session ID........: %x\n", serverHello.sessionID)
	out += fmt.Sprintf("  CipherSuite.......: %x\n", serverHello.cipherSuite)
	out += fmt.Sprintf("  CompressionMethod.: %x\n", serverHello.compressionMethod)
	out += fmt.Sprintf("  ExtensionLength...: %x\n", serverHello.extensionLength)
	//out += fmt.Sprintf("  ExtensionRenegInfo:%x\n", serverHello.extensionRenegotiationInfo)
	out += fmt.Sprintf("  Extension Renegotiation Info\n")
	out += fmt.Sprintf("    info:...........: %x\n", serverHello.extensionRenegotiationInfo.info)
	out += fmt.Sprintf("    length:.........: %x\n", serverHello.extensionRenegotiationInfo.length)
	out += fmt.Sprintf("    payload:........: %x\n", serverHello.extensionRenegotiationInfo.payload)

	return out
}

func main() {

	srvAddr := "heise.de:443"
	conn := connectToServer(srvAddr)

	//payload_http := "GET / HTTP/1.1\r\nHost: www.heise.de\r\nSome: hedder\r\n\r\n"
	clientHelloPayloadHex := "16030100a5010000a10303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000020cca8cca9c02fc030c02bc02cc013c009c014c00a009c009d002f0035c012000a010000580000001800160000136578616d706c652e756c666865696d2e6e6574000500050100000000000a000a0008001d001700180019000b00020100000d0012001004010403050105030601060302010203ff0100010000120000"
	sendToServer(conn, clientHelloPayloadHex)
	var answer []byte
	answer = readFromServer(conn)

	serverHello := parseHelloServer(answer)

	fmt.Println(serverHello)

	conn.Close()
}
