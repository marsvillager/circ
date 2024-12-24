use std::sync::Arc;
use circ_fields::FieldV;
use fxhash::FxHashMap as HashMap;
use rug::Integer;
use serde::{Serialize, Deserialize};
use crate::{ir::term::{Value, BitVector}, cfg::cfg};

/// This module contains the definitions and implementations for various witness types.
pub mod aes_witness;
pub mod channel_open_witness;
pub mod merkle_path_auth_witness;
pub mod non_membership_witness;
pub mod sha_round_witness;
/// test
pub mod test_witness;

/// A trait representing a witness that can be converted to a `WitnessMapper`.
pub trait Witness {
    /// Converts the witness into a `WitnessMapper`.
    fn to_map(&self) -> WitnessMapper;
}

/// A struct representing a witness mapper.
#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessMapper {
    /// A map of input names to their corresponding values.
    pub input_map: HashMap<String, Value>,
}

impl WitnessMapper {
    /// Creates a new `WitnessMapper` with an empty input map.
    pub fn new() -> Self {
        WitnessMapper {
            input_map: HashMap::<String, Value>::default(),
        }
    }

    /// Maps a field value to the input map.
    pub fn map_field<S: ToString>(&mut self, v: &S, name: &str) {
        self.input_map
            .insert(name.to_string(), str_to_field(v.to_string()));
    }

    /// Maps an 8-bit unsigned integer to the input map.
    pub fn map_u8(&mut self, v: u8, name: &str) {
        self.input_map.insert(name.to_string(), u8_to_value(v));
    }

    /// Maps a 16-bit unsigned integer to the input map.
    pub fn map_u16(&mut self, v: u16, name: &str) {
        self.input_map.insert(name.to_string(), u16_to_value(v));
    }

    /// Maps a 32-bit unsigned integer to the input map.
    pub fn map_u32(&mut self, v: u32, name: &str) {
        self.input_map.insert(name.to_string(), u32_to_value(v));
    }

    /// Maps a 64-bit unsigned integer to the input map.
    pub fn map_u64(&mut self, v: u64, name: &str) {
        self.input_map.insert(name.to_string(), u64_to_value(v));
    }

    /// Maps a padded array of 8-bit unsigned integers to the input map.
    pub fn map_u8_arr_padded(&mut self, v: &Vec<u8>, pad: usize, name: &str) {
        for (i, c) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), u8_to_value(c.clone()));
        }
        for i in v.len()..pad {
            self.input_map
                .insert(format!("{}.{}", name, i), u8_to_value(0));
        }
    }

    /// Maps a padded array of 32-bit unsigned integers to the input map.
    pub fn map_u32_arr_padded(&mut self, v: &Vec<u32>, pad: usize, name: &str) {
        for (i, c) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), u32_to_value(c.clone()));
        }
        for i in v.len()..pad {
            self.input_map
                .insert(format!("{}.{}", name, i), u32_to_value(0));
        }
    }

    /// Maps a padded array of field values to the input map.
    pub fn map_field_arr_padded<S: ToString>(&mut self, v: &Vec<S>, pad: usize, name: &str) {
        for (i, c) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), str_to_field(c.to_string().clone()));
        }
        for i in v.len()..pad {
            self.input_map
                .insert(format!("{}.{}", name, i), str_to_field("0".to_string()));
        }
    }

    /// Maps an array of field values to the input map.
    pub fn map_field_arr<S: ToString>(&mut self, v: &Vec<S>, name: &str) {
        for (i, s) in v.iter().enumerate() {
            self.input_map
                .insert(format!("{}.{}", name, i), str_to_field(s.to_string().clone()));
        }
    }
}

/// Converts an 8-bit unsigned integer to a `Value`.
fn u8_to_value(n: u8) -> Value {
    Value::BitVector(BitVector::new(Integer::from(n), 8))
}

/// Converts a 16-bit unsigned integer to a `Value`.
fn u16_to_value(n: u16) -> Value {
    Value::BitVector(BitVector::new(Integer::from(n), 16))
}

/// Converts a 32-bit unsigned integer to a `Value`.
fn u32_to_value(num: u32) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 32))
}

/// Converts a 64-bit unsigned integer to a `Value`.
fn u64_to_value(num: u64) -> Value {
    Value::BitVector(BitVector::new(Integer::from(num), 64))
}

/// Converts a string to a field value.
fn str_to_field(s: String) -> Value {
    let big_int = Integer::from_str_radix(&s, 10).unwrap();
    let field = cfg().field().modulus().clone();
    Value::Field(FieldV::new(big_int, Arc::new(field)))
}