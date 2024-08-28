use std::{path::{PathBuf, Path}, time::Instant, fs::File, io, io::{BufReader, BufWriter}};
use log::trace;
use bincode::{deserialize_from, serialize_into};
use serde::{de::DeserializeOwned, Serialize};

use circ::{
    cfg::{
        cfg,
        clap::{self, Parser, Subcommand},
        CircOpt,
    },
    front::{
        zsharp::{Inputs, ZSharpFE},
        FrontEnd, Mode,
    },
    ir::{
        opt::{opt, Opt},
        term::{text::parse_value_map, BV_LSHR, BV_SHL},
    },
    target::r1cs::{
        opt::reduce_linearities,
        trans::to_r1cs, 
        spartan,
    },
};

#[derive(Debug, Parser)]
#[command(name = "zkmb", about = "zero-knowledge middlebox")]
struct Options {
    #[command(flatten)]
    circ: CircOpt,

    #[structopt(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    Generate {
        // Input file
        #[arg(long, name = "PATH")]
        path: PathBuf,

        #[arg(long, default_value = "P")]
        prover_key: PathBuf,
    
        #[arg(long, default_value = "V")]
        verifier_key: PathBuf,
    },
    Prove {
        #[arg(long, default_value = "P")]
        prover_key: PathBuf,

        #[arg(long, default_value = "pin")]
        pin: PathBuf,

        #[arg(long, default_value = "gens")]
        gens_path: PathBuf,

        #[arg(long, default_value = "inst")]
        inst_path: PathBuf,

        #[arg(long, default_value = "proof")]
        proof_path: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "V")]
        verifier_key: PathBuf,

        #[arg(long, default_value = "vin")]
        vin: PathBuf,

        #[arg(long, default_value = "gens")]
        gens_path: PathBuf,

        #[arg(long, default_value = "inst")]
        inst_path: PathBuf,

        #[arg(long, default_value = "proof")]
        proof_path: PathBuf,
    },
}

fn write_to_path<P: AsRef<Path>, T: Serialize>(path: P, data: &T) -> io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    serialize_into(&mut file, &data).unwrap();
    Ok(())
}

fn read_from_path<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> io::Result<T> {
    let mut file = BufReader::new(File::open(path)?);
    let data: T = deserialize_from(&mut file).unwrap();
    Ok(data)
}

#[allow(unused_variables, unreachable_code)]
fn main() {
    env_logger::Builder::from_default_env()
        .format_level(false)
        .format_timestamp(None)
        .init();
    let options = Options::parse();
    circ::cfg::set(&options.circ);
    
    match options.action {
        Action::Generate{ path, prover_key, verifier_key } => {
            let mode = Mode::Proof;
            let inputs = Inputs {
                file: path,
                mode
            };
        
            println!("Running frontend");
            let timer = Instant::now();
            let cs = ZSharpFE::gen(inputs);
            println!("gen finish {} ms\n", timer.elapsed().as_millis());
        
            println!("Running IR optimizations");
            let timer = Instant::now();
            let cs = match mode {
                Mode::Opt => opt(
                    cs,
                    vec![Opt::ScalarizeVars, Opt::ConstantFold(Box::new([]))],
                ),
                Mode::Mpc(_) => {
                    let ignore = [BV_LSHR, BV_SHL];
                    opt(
                        cs,
                        vec![
                            Opt::ScalarizeVars,
                            Opt::Flatten,
                            Opt::Sha,
                            Opt::ConstantFold(Box::new(ignore.clone())),
                            Opt::Flatten,
                            // Function calls return tuples
                            Opt::Tuple,
                            Opt::Obliv,
                            // The obliv elim pass produces more tuples, that must be eliminated
                            Opt::Tuple,
                            Opt::LinearScan,
                            // The linear scan pass produces more tuples, that must be eliminated
                            Opt::Tuple,
                            Opt::ConstantFold(Box::new(ignore)),
                            // Binarize nary terms
                            Opt::Binarize,
                        ],
                        // vec![Opt::Sha, Opt::ConstantFold, Opt::Mem, Opt::ConstantFold],
                    )
                }
                Mode::Proof | Mode::ProofOfHighValue(_) => {
                    let mut opts = Vec::new();
        
                    opts.push(Opt::ConstantFold(Box::new([])));
                    opts.push(Opt::DeskolemizeWitnesses);
                    opts.push(Opt::ScalarizeVars);
                    opts.push(Opt::Flatten);
                    opts.push(Opt::Sha);
                    opts.push(Opt::ConstantFold(Box::new([])));
                    opts.push(Opt::ParseCondStores);
                    // Tuples must be eliminated before oblivious array elim
                    opts.push(Opt::ConstantFold(Box::new([])));
                    opts.push(Opt::Obliv);
                    // The obliv elim pass produces more tuples, that must be eliminated
                    opts.push(Opt::SetMembership);
                    opts.push(Opt::PersistentRam);
                    opts.push(Opt::VolatileRam);
                    if options.circ.ir.fits_in_bits_ip {
                        opts.push(Opt::FitsInBitsIp);
                    }
                    opts.push(Opt::SkolemizeChallenges);
                    opts.push(Opt::ScalarizeVars);
                    opts.push(Opt::ConstantFold(Box::new([])));
                    opts.push(Opt::Obliv);
                    opts.push(Opt::LinearScan);
                    // The linear scan pass produces more tuples, that must be eliminated
                    opts.push(Opt::Tuple);
                    opts.push(Opt::Flatten);
                    opts.push(Opt::ConstantFold(Box::new([])));
                    opt(cs, opts)
                }
            };
            println!("opt finish {} ms\n", timer.elapsed().as_millis());
        
            println!("Running backend");
            let cs = cs.get("main");
            trace!("IR: {}", circ::ir::term::text::serialize_computation(cs));
            let mut r1cs = to_r1cs(cs, cfg());
            println!("R1CS cons before reduce linearity {}", r1cs.constraints().len());
            println!("R1CS stats: {:#?}", r1cs.stats());
        
            println!("Running r1cs optimizations");
            r1cs = reduce_linearities(r1cs, cfg());
        
            println!("R1CS cons after reduce linearity {}", r1cs.constraints().len());
            println!("R1CS stats: {:#?}", r1cs.stats());
        
            let (prover_data, verifier_data) = r1cs.finalize(cs);
            println!(
                "Final R1cs rounds: {}",
                prover_data.precompute.stage_sizes().count() - 1
            );
            spartan::write_data::<_, _>(prover_key, verifier_key, &prover_data, &verifier_data)
                .unwrap();
        }
        Action::Prove { prover_key, pin, gens_path, inst_path, proof_path} => {
            let prover_input_map = parse_value_map(&std::fs::read(pin).unwrap());
            println!("Spartan Proving");
            let (gens, inst, proof) = spartan::prove(prover_key, &prover_input_map, options.circ.field.builtin).unwrap(); 
            write_to_path::<_, _>(gens_path, &gens).unwrap(); // public parameters
            write_to_path::<_, _>(inst_path, &inst) .unwrap(); // instance
            write_to_path::<_, _>(proof_path, &proof).unwrap(); // proof
        }
        Action::Verify { verifier_key, vin, gens_path, inst_path, proof_path } => {
            let verifier_input_map = parse_value_map(&std::fs::read(vin).unwrap());
            println!("Spartan Verifying");
            let gens = read_from_path::<_, _>(gens_path).unwrap();
            let inst = read_from_path::<_, _>(inst_path).unwrap();
            let proof = read_from_path::<_, _>(proof_path).unwrap();
            spartan::verify(verifier_key, &verifier_input_map, &gens, &inst, proof).unwrap();
        }
    }
}