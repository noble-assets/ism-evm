use tonic::{Request, Response, Status};
use tracing::{error, info, instrument};

use crate::config::Config;
use crate::prover::{light_client, merkle};

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
    #[instrument(skip(self), fields(slot))]
    async fn ethereum_hyperlane_root(
        &self,
        request: Request<EthereumHyperlaneRootRequest>,
    ) -> Result<Response<EthereumHyperlaneRootResponse>, Status> {
        let slot = request.into_inner().slot;
        tracing::Span::current().record("slot", slot);

        info!("Received proof request");

        // Prepare inputs
        let (lc_input_result, merkle_input_result) = tokio::join!(
            light_client::prepare_input(
                slot,
                &self.config.eth_beacon_rpc,
                &self.config.eth_execution_rpc,
                &self.config.light_client_contract,
                self.config.chain_id
            ),
            merkle::prepare_input(slot, &self.config.eth_execution_rpc),
        );

        let lc_input = lc_input_result.map_err(|e| {
            error!(error = %e, "Failed to prepare light client input");
            Status::internal(e.to_string())
        })?;

        let merkle_input = merkle_input_result.map_err(|e| {
            error!(error = %e, "Failed to prepare merkle input");
            Status::internal(e.to_string())
        })?;

        // Generate proofs in parallel
        info!("Starting parallel proof generation");
        let (lc_result, merkle_result) =
            tokio::join!(light_client::prove(lc_input), merkle::prove(merkle_input),);

        let (proof_lc, inputs_lc) = lc_result.map_err(|e| {
            error!(error = %e, "Light client proof failed");
            Status::internal(e)
        })?;

        let (proof_ism, inputs_ism) = merkle_result.map_err(|e| {
            error!(error = %e, "Hyperlane merkle proof failed");
            Status::internal(e)
        })?;

        info!("Proof generation complete");

        Ok(Response::new(EthereumHyperlaneRootResponse {
            proof_light_client: proof_lc,
            public_inputs_light_client: inputs_lc,
            proof_ism,
            public_inputs_ism: inputs_ism,
        }))
    }
}
