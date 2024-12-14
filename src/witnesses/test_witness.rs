use serde::Deserialize;
use super::{Witness, WitnessMapper};

/// Represents a witness for the prover in the channel opening process.
#[derive(Deserialize)]
pub struct TestProverWitness {
    /// test
    pub y: String,
}

impl Witness for TestProverWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.y, "y");
        mapper
    }
}

/// Represents a witness for the verifier in the channel opening process.
#[derive(Deserialize)]
pub struct TestVerifierWitness {
    /// test
    pub value: String,
}

impl Witness for TestVerifierWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field(&self.value, "return");
        mapper
    }
}