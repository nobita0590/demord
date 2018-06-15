package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	fmt.Println(tls.TLS_RSA_WITH_RC4_128_SHA)
	fmt.Println(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	fmt.Println(tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	fmt.Println(tls.TLS_RSA_WITH_AES_256_CBC_SHA)
	fmt.Println(tls.TLS_RSA_WITH_AES_128_CBC_SHA256)
	fmt.Println(tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
	fmt.Println(tls.TLS_RSA_WITH_AES_256_GCM_SHA384)
	fmt.Println(tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
	fmt.Println(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
}