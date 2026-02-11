set dotenv-load

# Generate VKs + fetch beacon checkpoint, append all to .env
bootstrap:
    cargo run --bin bootstrap

# Deploy EthereumLightClient and EthereumISM
# Usage: just deploy 0xYourOwnerAddress
deploy owner:
    cd contracts && \
    OWNER={{owner}} forge script script/Deploy.s.sol \
        --rpc-url $RPC_URL \
        --broadcast \
        --private-key $PRIVATE_KEY \
        --verify \
        --verifier blockscout \
        --verifier-url $VERIFIER_URL \
        -vvvv
