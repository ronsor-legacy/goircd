package main

import "math/rand"
import "fmt"
func uniqid() string {
	return fmt.Sprintf("%010X", rand.Intn(0xCFFFFFFFFF)+0x1000000000)
}
