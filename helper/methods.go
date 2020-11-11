package main

import (
	"fmt"
)

type Aaaa struct {
	rand0 int
	rand1 []byte
}

type Bbbb struct {
	rand2 int
	tand3 []byte
}

type Both struct {
	aaaa Aaaa
	bbbb Bbbb
}

func (aaaa Aaaa) String() string {
	out := "start Aaaa\n"
	out += fmt.Sprintf("rand1: %x\n", aaaa.rand1)
	out += "end Aaaa\n"
	return out
}

func (bbbb Bbbb) String() string {
	out := "start Bbbb\n"
	out += fmt.Sprintf("rand1: %x\n", bbbb.tand3)
	out += "end Aaaa\n"
	return out
}

func (both Both) String() string {
	out := "bothstart\n"
	out += fmt.Sprintf("%s:\n", both.aaaa)
	out += fmt.Sprintf("%s:\n", both.bbbb)
	out += "bothend\n"
	return out

}

func main() {
	aaaa := Aaaa{10, []byte{123, 222}}
	fmt.Println(aaaa)

	bbbb := Bbbb{10, []byte{123, 222}}
	fmt.Println(bbbb)

	both := Both{aaaa, bbbb}
	fmt.Println(both)
}
