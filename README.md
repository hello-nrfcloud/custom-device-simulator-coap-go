# `hello.nrfcloud.com/map` custom device simulator

Implements a custom device on `hello.nrfcloud.com/map` that connects to nRF Cloud using CoAP and sends LwM2M objects using senML encoded as CBOR.

## Build

```bash
go build
```

## Usage

```bash
./device-simulator-coap -deviceId <deviceId> -privateKey <path to private key> <<< "<SenML JSON>"
```

See [senml.schema.json](./senml.schema.json) for the expected SenML JSON format.

The key file should be a private key as PEM, without EC params (they are not supported by pion/dtls).
