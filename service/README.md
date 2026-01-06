# Prover Service

gRPC service for generating SP1 Groth16 proofs for Ethereum light client updates and Hyperlane merkle roots.

## Environment Variables

Set the env variables in an .env file like the example provided.

| Variable                | Required | Default | Description                                         |
| ----------------------- | -------- | ------- | --------------------------------------------------- |
| `ETH_BEACON_RPC`        | Yes      | -       | Ethereum Beacon Chain RPC endpoint                  |
| `ETH_EXECUTION_RPC`     | Yes      | -       | Ethereum Execution Layer RPC endpoint               |
| `NETWORK_PRIVATE_KEY`   | Yes      | -       | Private key for SP1 network prover authentication   |
| `LIGHT_CLIENT_CONTRACT` | Yes      | -       | Address of the light client contract                |
| `API_KEY`               | Yes      | -       | API key for authenticating requests to this service |
| `CHAIN_ID`              | No       | `1`     | Chain ID (1 for Mainnet, 11155111 for Sepolia)      |
| `PORT`                  | No       | `50051` | gRPC server port                                    |

## Running the Service

The service can be run either natively with Cargo or via Docker.

### Native

```bash
cargo run --release
```

### Docker

Build from project root:

```bash
docker build -t prover-service .
```

Run with environment variables in a `.env` file:

```bash
docker run --rm -p 50051:50051 --env-file .env --name prover prover-service
```

## Testing

```bash
grpcurl -plaintext \
  -proto ./proto/prover.proto \
  -H "x-api-key: $API_KEY" \
  localhost:50051 proto.Prover/EthereumHyperlaneRoot
```
