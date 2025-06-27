package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	data := os.Args[1]
	if data == "" {
		fmt.Println("Please provide a string to hash.")
		return
	}

	hash := sha256.New()
	hash.Write([]byte(data))
	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)
	fmt.Println(hashString)
}
