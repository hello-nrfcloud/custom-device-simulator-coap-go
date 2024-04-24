package main

import (
	"bytes"
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
	"github.com/plgd-dev/go-coap/v3/message/pool"
	udpClient "github.com/plgd-dev/go-coap/v3/udp/client"

	"crypto/ecdsa"
	"log"

	"github.com/golang-jwt/jwt"

	senMLCodec "github.com/farshidtz/senml/v2/codec"

	"encoding/hex"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func loadPrivateKey(privateKeyPath string) (*ecdsa.PrivateKey, error) {
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

func createJWTToken(privateKeyPath string, deviceID string) (string, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	expirationTime := time.Now().Add(10 * time.Minute).Unix()

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
	privateKeyPath := flag.String("privateKey", "", "The private key file")
	flag.Parse()

	if *deviceId == "" {
		log.Fatal("Must provide a deviceId!")
	}
	log.Println("DeviceID:", *deviceId)

	token, err := createJWTToken(*privateKeyPath, *deviceId)
	if err != nil {
		log.Fatalf("Failed to create JWT token: %v", err)
	}

	log.Println("JWT Token:", token)

	// Connect to a DTLS server
	co, err := dtls.Dial("coap.nrfcloud.com:5684", &piondtls.Config{
		InsecureSkipVerify:    true,
		ConnectionIDGenerator: piondtls.OnlySendCIDGenerator(),
	})
	util.Check(err)
	defer func() {
		util.Check(co.Close())
	}()

	log.Println("Connected.")

	// Authenticate
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := co.Post(ctx, "/auth/jwt", message.TextPlain, strings.NewReader(token))
	check(err)
	checkResponse(resp, codes.Created)
	// assertEquals(Code.C201_CREATED, resp.code)
	// assertTrue(resp.options().maxAge > 0)

	log.Println("Authenticated.")

	getState(co)
	publishSenML(co)
}

func checkResponse(resp *pool.Message, expected codes.Code) {
	if resp.Code() != expected {
		panic(fmt.Sprintf(`Request failed: %d`, resp.Code()))
	}
}

func getState(co *udpClient.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get the state
	// options := []message.Option{
	// 	{ID: message.Accept, Value: []byte(message.TextPlain.String())},
	// 	{ID: message.URIQuery, Value: []byte("?transform=pairing")},
	// }
	// stateResp, err := co.Get(ctx, "/state", options...)
	stateResp, err := co.Get(ctx, "/state")
	check(err)
	checkResponse(stateResp, codes.Content)
	data, err := io.ReadAll(stateResp.Body())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("< State: %s\n", data)
}

func publishSenML(co *udpClient.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Read JSON from stdin
	senMLJSON, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err) // handle the error
	}

	senMLPayload, err := senMLCodec.DecodeJSON([]byte(senMLJSON))
	if err != nil {
		panic(err) // handle the error
	}

	// validate the SenML Pack
	err = senMLPayload.Validate()
	if err != nil {
		panic(err) // handle the error
	}

	// encode the normalized SenML Pack to CBOR
	dataOut, err := senMLCodec.EncodeCBOR(senMLPayload)
	if err != nil {
		panic(err) // handle the error
	}

	// Convert dataOut to hex string
	dataOutHex := hex.EncodeToString(dataOut)
	log.Printf("> /msg/d2c/raw: %s (hex encoded)\n", dataOutHex)
	log.Printf("> %s", senMLJSON)

	rawResp, err := co.Post(ctx, "/msg/d2c/raw", message.AppCBOR, bytes.NewReader(dataOut))
	check(err)
	checkResponse(rawResp, codes.Created)
}
