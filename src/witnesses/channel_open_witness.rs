use serde::Deserialize;
use super::{Witness, WitnessMapper};

/// Represents a witness for the prover in the channel opening process.
#[derive(Deserialize)]
pub struct ChannelOpenProverWitness {
    /// Hash of the handshake message.
    pub hs: Vec<u8>,
    /// Hash of the second message.
    pub h2: Vec<u8>,
    /// Length of the client-server handshake.
    pub ch_sh_len: u16,
    /// Length of the server extension.
    pub serv_ext_len: u16,
    /// Tail of the server extension ciphertext.
    pub serv_ext_ct_tail: Vec<u8>,
    /// Length of the tail of the server extension.
    pub serv_ext_tail_len: u8,
    /// Checkpoint of the SHA hash.
    pub sha_h_checkpoint: Vec<u32>,
    /// Commitment string.
    pub comm: String,
}

impl Witness for ChannelOpenProverWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_u8_arr_padded(&self.hs, 32, "HS");
        mapper.map_u8_arr_padded(&self.h2, 32, "H2");
        mapper.map_u16(self.ch_sh_len, "CH_SH_len");
        mapper.map_u16(self.serv_ext_len, "ServExt_len");
        mapper.map_u8_arr_padded(&self.serv_ext_ct_tail, 128, "ServExt_ct_tail");
        mapper.map_u8(self.serv_ext_tail_len, "ServExt_tail_len");
        mapper.map_u32_arr_padded(&self.sha_h_checkpoint, 8, "SHA_H_Checkpoint");
        mapper.map_field(&self.comm, "comm");
        mapper
    }
}

/// Represents a witness for the verifier in the channel opening process.
#[derive(Deserialize)]
pub struct ChannelOpenVerifierWitness {
    /// Hash of the second message.
    pub h2: Vec<u8>,
    /// Length of the client-server handshake.
    pub ch_sh_len: u16,
    /// Length of the server extension.
    pub serv_ext_len: u16,
    /// Tail of the server extension ciphertext.
    pub serv_ext_ct_tail: Vec<u8>,
    /// Length of the tail of the server extension.
    pub serv_ext_tail_len: u8,
    /// Commitment string.
    pub comm: String,
}

impl Witness for ChannelOpenVerifierWitness {
    fn to_map(&self) -> WitnessMapper {
        let mut mapper = WitnessMapper::new();
        mapper.map_field_arr_padded(&self.h2, 32, "H2");
        mapper.map_field(&self.ch_sh_len, "CH_SH_len");
        mapper.map_field(&self.serv_ext_len, "ServExt_len");
        mapper.map_field_arr_padded(&self.serv_ext_ct_tail, 128, "ServExt_ct_tail");
        mapper.map_field(&self.serv_ext_tail_len, "ServExt_tail_len");
        mapper.map_field(&self.comm, "comm");
        mapper.map_field(&"1".to_string(), "return");
        mapper
    }
}