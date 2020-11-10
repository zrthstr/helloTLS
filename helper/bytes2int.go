package main

import "fmt"
import "encoding/binary"

func main() {
	var mySlice = [4]byte{244, 244, 244, 244}
	data := binary.LittleEndian.Uint64(mySlice)
	fmt.Println(data)
}
