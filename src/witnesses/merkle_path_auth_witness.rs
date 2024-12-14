use serde::Deserialize;
use super::{Witness, WitnessMapper};

/// Represents a witness for the prover in the channel opening process.
#[derive(Deserialize)]
pub struct MerklePathAuthProverWitness {
    pub leaf: String,
    pub direction_selector: u64,
    pub digests: Vec<String>,
}

impl Witness for MerklePathAuthProverWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.leaf, "leaf");
		mapper.map_u64(self.direction_selector, "direction_selector");
		mapper.map_field_arr_padded(&self.digests, 21, "digests");
        mapper
    }
}

/// Represents a witness for the verifier in the channel opening process.
#[derive(Deserialize)]
pub struct MerklePathAuthVerifierWitness {
    pub root: String,
}

impl Witness for MerklePathAuthVerifierWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.root, "root");
        mapper
    }
}