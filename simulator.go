package main

import (
	"bytes"
	"context"
	"device-simulator-coap/lwm2m"
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

	"crypto/ecdsa"
	"log"

	"github.com/golang-jwt/jwt"

	senML "github.com/farshidtz/senml/v2"
	senMLCodec "github.com/farshidtz/senml/v2/codec"

	"encoding/hex"
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

	log.Println("DeviceID:", *deviceId)

	token, err := createJWTToken(*deviceId)
	if err != nil {
		log.Fatalf("Failed to create JWT token: %v", err)
	}

	log.Println("JWT Token:", token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	resp, err := co.Post(ctx, "/auth/jwt", message.TextPlain, strings.NewReader(token))
	check(err)
	checkResponse(resp, codes.Created)
	// assertEquals(Code.C201_CREATED, resp.code)
	// assertTrue(resp.options().maxAge > 0)

	// Get the state
	stateResp, err := co.Get(ctx, "/state")
	check(err)
	checkResponse(stateResp, codes.Content)
	data, err := io.ReadAll(stateResp.Body())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("State: %s\n", data)

	// Send LwM2M Geolocation object CBOR encoded SenML
	ts := float64(time.Now().UnixMilli())
	lat := 62.469414
	lng := 6.151946
	accuracy := 1.0
	source := "Fixed"
	senMLPayload := senML.Pack{
		{BaseName: fmt.Sprintf("%d/0/", lwm2m.Geolocation_14201),
			BaseTime: ts,
			Name:     "0", Value: &lat,
		},
		{Name: "1", Value: &lng},
		{Name: "3", Value: &accuracy},
		{Name: "6", StringValue: source},
	}

	err = senMLPayload.Validate()
	if err != nil {
		panic(err) // handle the error
	}
	senMLPayload.Normalize()

	// encode the normalized SenML Pack to XML
	dataOut, err := senMLCodec.EncodeCBOR(senMLPayload)
	if err != nil {
		panic(err) // handle the error
	}

	// Convert dataOut to hex string
	dataOutHex := hex.EncodeToString(dataOut)
	log.Printf("> /msg/d2c/raw: %s (hex encoded)\n", dataOutHex)

	rawResp, err := co.Post(ctx, "/msg/d2c/raw", message.AppCBOR, bytes.NewReader(dataOut))
	check(err)
	checkResponse(rawResp, codes.Created)
	log.Printf("Published location")

}

func checkResponse(resp *pool.Message, expected codes.Code) {
	if resp.Code() != expected {
		panic(fmt.Sprintf(`Request failed: %d`, resp.Code()))
	}
}
