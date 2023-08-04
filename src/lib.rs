#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "docs", deny(missing_docs))]
#![cfg_attr(feature = "docs", doc = include_str!("../README.md"))]
#![cfg_attr(feature = "docs", doc(html_root_url = "https://docs.rs/bulletproofs/4.0.0"))]

extern crate alloc;
extern crate serde_derive;

mod util;

#[cfg_attr(feature = "docs", doc = include_str!("../docs/notes-intro.md"))]
mod notes {
    #[cfg_attr(feature = "docs", doc = include_str!("../docs/notes-ipp.md"))]
    mod inner_product_proof {}
    #[cfg_attr(feature = "docs", doc = include_str!("../docs/notes-rp.md"))]
    mod range_proof {}
    #[cfg_attr(feature = "docs", doc = include_str!("../docs/notes-r1cs.md"))]
    mod r1cs_proof {}
}

mod errors;
mod generators;
mod inner_product_proof;
// TODO: Do not expose `range_proof` publicly
pub mod range_proof;
mod transcript;

pub use crate::{
    errors::ProofError,
    generators::{BulletproofGens, BulletproofGensShare, PedersenGens},
    range_proof::RangeProof,
};

#[cfg_attr(feature = "docs", doc = include_str!("../docs/aggregation-api.md"))]
pub mod range_proof_mpc {
    pub use crate::{
        errors::MPCError,
        range_proof::{dealer, messages, party},
    };
}

#[cfg(feature = "yoloproofs")]
#[cfg(feature = "std")]
pub mod r1cs;
