//! This package contains the concrete proving logic to generate a
//! proof for the BLS12-381 signature verification over a finalized Noble
//! EVM block proposal.

use alloy_primitives::Bytes;
use alloy_sol_types::sol;
use alloy_rpc_types_eth::Header;
use serde::{Deserialize, Serialize};
use commonware_consensus::simplex::types::{Finalization, Proposal};
use commonware_codec::extensions::DecodeExt as _;
use noble_consensus_common::{B256Ext as _, FixedBytesExt as _, Variant};

// TODO: fill with expected value once known -- enable testnet/mainnet different keys too
const TRUSTED_NOBLE_NETWORK_KEY: &str = "0x";

/// This struct holds the information required for the 
#[derive(Deserialize, Serialize)]
pub struct BLSVerifierInputs {
    /// The header of the signed block on the Noble EVM chain.
    header: Header<noble_primitives::header::NobleHeader>,

    /// The finalization certificate signed by the aggregated
    /// BLS12-381 private key in MinSig variation
    /// (48 bytes signature; 96 bytes public key).
    certificate: Bytes,
}

sol!(
    struct BLSVerifierOutputs {
        uint64 blockNumber;
        bytes32 stateRoot;
        string publicKey;
    }
);

pub fn prove(input: &BLSVerifierInputs) -> Result<BLSVerifierOutputs, Box<dyn std::error::Error>> {
    let context = input.header.consensus_context.to_context();

    let certificate = <noble_dkg::orchestrator::ThresholdScheme as commonware_cryptography::certificate::Scheme>::Certificate::decode(
        input.certificate.clone()
    )?;

    let group_public_key = <Variant as commonware_cryptography::bls12381::primitives::variant::Variant>::Public::decode(
        TRUSTED_NOBLE_NETWORK_KEY.as_ref(),
    )?;

    let proposal = Proposal::new(
        context.round,
        context.parent.0, // the parent's view
        input.header.hash.to_digest(),
    );

    let verifier = noble_dkg::orchestrator::ThresholdScheme::certificate_verifier(
        noble_consensus_application::constants::NAMESPACE,
        group_public_key,
    );

    let finalization = Finalization::<
        noble_dkg::orchestrator::ThresholdScheme,
        commonware_cryptography::sha256::Digest,
    > {
        proposal,
        certificate
    };

    let mut rng = rand::thread_rng();
    if !finalization.verify(
        &mut rng,
        &verifier,
        &commonware_parallel::Sequential
    ) {
        return Err(eyre::eyre!("failed to verify finalization certificate").into());
    }

    Ok(
        BLSVerifierOutputs {
            blockNumber: input.header.number,
            publicKey: TRUSTED_NOBLE_NETWORK_KEY.to_string(),
            stateRoot: input.header.state_root,
        }
    )
}