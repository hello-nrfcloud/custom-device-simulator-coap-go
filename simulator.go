package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	piondtls "github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"

	"crypto/ecdsa"
	"log"

	"github.com/golang-jwt/jwt"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func loadPrivateKey(deviceID string) (*ecdsa.PrivateKey, error) {
	privateKeyPath := fmt.Sprintf("certificates/%s.key", deviceID)
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func createJWTToken(deviceID string) (string, error) {
	privateKey, err := loadPrivateKey(deviceID)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	expirationTime := time.Now().Add(10 * time.Minute).Unix()

	fmt.Println("Expires", expirationTime)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.StandardClaims{
		Subject:   deviceID,
		ExpiresAt: expirationTime,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func main() {
	deviceId := flag.String("deviceId", "", "The client ID.")
	flag.Parse()

	if *deviceId == "" {
		log.Fatal("Must provide a deviceId!")
	}

	fmt.Println("DeviceID:", *deviceId)

	token, err := createJWTToken(*deviceId)
	if err != nil {
		log.Fatalf("Failed to create JWT token: %v", err)
	}

	fmt.Println("JWT Token:", token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to a DTLS server
	co, err := dtls.Dial("coap.nrfcloud.com:5684", &piondtls.Config{
		InsecureSkipVerify: true,
	})
	util.Check(err)
	defer func() {
		util.Check(co.Close())
	}()

	fmt.Println("Connected.")

	// Authenticate

	resp, err := co.Post(ctx, "/auth/jwt", message.TextPlain, strings.NewReader(token))
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	for _, option := range resp.Options() {
		fmt.Println("Option:", option.ID, option.Value)
	}
	if resp.Code() != codes.Created {
		bodySize, err := resp.BodySize()
		check(err)
		if bodySize > 0 {
			data, err := io.ReadAll(resp.Body())
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("%s\n", data)
		}
		log.Fatalf("Authentication failed: %d", resp.Code())
	}
	fmt.Println(resp.Code())
	// assertEquals(Code.C201_CREATED, resp.code)
	// assertTrue(resp.options().maxAge > 0)

	/*
		devicesPath := fmt.Sprintf("/v1/devices/%s?transform=tenantId", *deviceId)
		fmt.Println("Path:", devicesPath)

		resp, err := co.Get(ctx, devicesPath)
		if err != nil {
			log.Fatalf("Error sending request: %v", err)
		}
		data, err := io.ReadAll(resp.Body())
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s\n", data)
	*/
}
