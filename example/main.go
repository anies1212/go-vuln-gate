// Package main demonstrates a vulnerable Go application for testing go-vuln-gate.
package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func main() {
	// golang.org/x/net/html - has known vulnerabilities in older versions
	// This call triggers the vulnerability check
	htmlStr := "<html><body><p>Hello World</p></body></html>"
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		fmt.Printf("Error parsing HTML: %v\n", err)
		return
	}
	fmt.Printf("Parsed HTML document: %v\n", doc.Type)

	fmt.Println("This is a test application with intentionally vulnerable dependencies.")
	fmt.Println("Run go-vuln-gate to detect these vulnerabilities.")
}
