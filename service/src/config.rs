use alloy_primitives::Address;

#[derive(Clone)]
pub struct Config {
    pub eth_beacon_rpc: String,
    pub eth_execution_rpc: String,
    pub chain_id: u64,
    pub light_client_contract: Address,
    pub port: String,
}

impl Config {
    pub fn from_env() -> Self {
        // Will panic if any required env var is missing
        std::env::var("NETWORK_PRIVATE_KEY").expect("NETWORK_PRIVATE_KEY must be set in .env");

        Self {
            eth_beacon_rpc: std::env::var("ETH_BEACON_RPC").expect("ETH_BEACON_RPC must be set"),
            eth_execution_rpc: std::env::var("ETH_EXECUTION_RPC")
                .expect("ETH_EXECUTION_RPC must be set"),
            chain_id: std::env::var("CHAIN_ID")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .expect("CHAIN_ID must be a valid u64"),
            light_client_contract: std::env::var("LIGHT_CLIENT_CONTRACT")
                .expect("LIGHT_CLIENT_CONTRACT must be set")
                .parse()
                .expect("LIGHT_CLIENT_CONTRACT must be a valid address"),
            port: std::env::var("PORT").unwrap_or_else(|_| "50051".to_string()),
        }
    }
}
