use alloy_sol_types::SolValue;
use tonic::{Request, Response, Status};
use tracing::{error, info, instrument};

use crate::config::Config;
use crate::prover::{light_client, merkle};
use crate::server::proto::{NobleHyperlaneRootRequest, NobleHyperlaneRootResponse};

pub mod proto {
    tonic::include_proto!("proto");
}

use proto::prover_server::Prover;
use proto::{EthereumHyperlaneRootRequest, EthereumHyperlaneRootResponse};

pub struct ProverService {
    config: Config,
}

impl ProverService {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[tonic::async_trait]
impl Prover for ProverService {
    #[instrument(skip(self))]
    async fn ethereum_hyperlane_root(
        &self,
        _request: Request<EthereumHyperlaneRootRequest>,
    ) -> Result<Response<EthereumHyperlaneRootResponse>, Status> {
        info!("Received proof request");

        // Prepare inputs
        let lc_input_result = light_client::prepare_input(
            &self.config.eth_beacon_rpc,
            &self.config.execution_rpc,
            &self.config.light_client_contract,
            self.config.chain_id,
        )
        .await;

        let (lc_input, block_number) = lc_input_result.map_err(|e| {
            error!(error = %e, "Failed to prepare light client input");
            Status::internal(e.to_string())
        })?;

        let merkle_input_result = merkle::prepare_input(
            self.config.chain_id,
            block_number,
            &self.config.eth_execution_rpc,
        )
        .await;

        let merkle_input = merkle_input_result.map_err(|e| {
            error!(error = %e, "Failed to prepare merkle input");
            Status::internal(e.to_string())
        })?;

        // Generate proofs in parallel
        info!("Starting parallel proof generation");
        let (lc_result, merkle_result) =
            tokio::join!(light_client::prove(lc_input), merkle::prove(merkle_input),);

        let proof_lc = lc_result.map_err(|e| {
            error!(error = %e, "Light client proof failed");
            Status::internal(e)
        })?;

        let proof_ism = merkle_result.map_err(|e| {
            error!(error = %e, "Hyperlane merkle proof failed");
            Status::internal(e)
        })?;
        info!("Proof generation complete");

        // Extract the hyperlane root from the merkle public inputs to return it in the response
        // Safe to unwrap as the proof generation would have failed otherwise
        let output =
            primitives::hyperlane::Output::abi_decode_validate(proof_ism.public_values.as_slice())
                .unwrap();
        let hyperlane_root = output.root.to_vec();

        Ok(Response::new(EthereumHyperlaneRootResponse {
            proof_light_client: proof_lc.bytes().to_vec(),
            public_values_light_client: proof_lc.public_values.to_vec(),
            proof_ism: proof_ism.bytes().to_vec(),
            public_values_ism: proof_ism.public_values.to_vec(),
            hyperlane_root,
        }))
    }

    // This function serves the endpoint to generate the corresponding Hyperlane Merke root proof
    // for the Noble EVM. It is using the same methods as the Ethereum endpoint above, but does not
    // require running the light client proof.
    async fn noble_hyperlane_root(&self, _request: Request<NobleHyperlaneRootRequest>) -> Result<Response<NobleHyperlaneRootResponse>, Status> {
        todo!("implement me!")
    }
}
