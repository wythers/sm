package main

import (
	"context"
	"fmt"
	"log"

	"github.com/wythers/sm/client/tron"
)

func main() {
	c := tron.NewClient(context.Background(), "https://api.trongrid.io")

	balance, err := c.GetTRXBalance("TCSo5RSBTZUwMzUZAu2NfbYWzKbE43fywM")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(balance)
}
