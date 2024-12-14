use std::{path::{PathBuf, Path}, time::Instant, fs::File, io, io::{BufReader, BufWriter}};
use log::trace;
use bincode::{deserialize_from, serialize_into};
use serde::{de::DeserializeOwned, Serialize};

use circ::{
    cfg::{
        cfg, clap::{self, Parser, Subcommand}, set, CircOpt
    },
    front::{
        zsharp::{Inputs, ZSharpFE},
        FrontEnd, Mode,
    },
    ir::{
        opt::{opt, Opt},
        term::{text, BV_LSHR, BV_SHL},
    },
    target::r1cs::{
        opt::reduce_linearities, spartan, trans::to_r1cs
    },
    witnesses::{
        Witness, 
        test_witness::*,
        merkle_path_auth_witness::*, 
        non_membership_witness::*, 
        channel_open_witness::*, 
    }
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

        #[arg(long)]
        pin: Option<PathBuf>,

        #[arg(long)]
        witness: Option<String>,

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

        #[arg(long)]
        vin: Option<PathBuf>,

        #[arg(long)]
        witness: Option<String>,

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
    set(&options.circ);
    
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
            trace!("IR: {}", text::serialize_computation(cs));
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
        Action::Prove { prover_key, pin, witness, gens_path, inst_path, proof_path} => {
            let prover_input_map;  
            
            if let Some(pin_path) = pin {  
                prover_input_map = text::parse_value_map(&std::fs::read(pin_path).unwrap());
            } else if let Some(prover_witness) = witness { 
                let prover_witness: Box<dyn Witness> = match prover_witness.as_str() {
                    "test" => Box::new(TestProverWitness {  // ./examples/ZoKrates/pf/arr_str_arr_str.zok.pin
                        y: "4".to_string()
                    }),
                    "merkle_path_auth" => Box::new(MerklePathAuthProverWitness {
                        leaf: "9817580614032284009472102877315339047595385576831075091947210607949273826813".to_string(),
                        direction_selector: 797055,
                        digests: vec!["20371957316706590367026574135697725825887796829306158222557991621197466431469", "637088382806173630874776885821089335531265646715079444847786964404775619113", "12602037159399515188457340003446787126828600509992398154723129763258638923467", "9146310747645687131151338652963772462153169836688804346351673391183057682302", "6662556348221049621097519812645513042144188409592383212691096750725804609846", "5230915819145317658164393841072272156151142032440437302803318224729671573859", "19832156907423339133803834134140326261870241292318575319913178943019834348494", "6905872216741174000525490198592230306463679688820865872464378779418307540558", "8155362764709398578587443640501903888821971166757258278813831856235205436710", "2033088050386922372024678621255434593091105709306196810312271943500979301919", "8658703974207291566573323916635255605084432382292002607136098055442707527167", "1185222556422479356219466065066586799595405762743257768817229382538110916587", "4580890167902279853405749084388948515631617304057625180374787545698768130179", "12718565543998551886931350346565446549554015647219184531648742196599818499177", "19263591617735962881447424550135800583224408966678876579016952550708836562677", "575529043309759006021566786411231943067598842483629924903517148234982503584", "19205095382443182505018596608049436058483223195556804077552346290391885721453", "17780337547445437654150464931522903071886786264428269918342389871067138260149", "5838158816163414142993856105097503668654938347650195326910792466710011581529", "11212789970948969852418853273145065376961075048592548698592712801777880643612", "12065566107138215118032764005282735623823121980929973141693816115916654749181"].into_iter().map(|s| s.to_string()).collect()
                    }),
                    "non_membership" => Box::new(NonMembershipProverWitness {
                        input_domain_name_wildcard: "moc.nozama.".chars().map(|c| (c as u8)).collect(),
                        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
                        left_domain_name: "moc.nozalleb.".chars().map(|c| (c as u8)).collect(),
                        right_domain_name: "moc.nozamaainat.".chars().map(|c| (c as u8)).collect(),
                        left_index: 8,
                        right_index: 10,
                        left_path_array: vec!["5810949145975268983677078150180109141833000559744284858058387945943982818158", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].into_iter().map(|s| s.to_string()).collect(),
                        right_path_array: vec!["4839109933088249563345538684967196188604080928683251255855801088884596272688", "5725556692859964327615384670197743052032183597439067324056707782326754149039", "737987365019311986891486759646137884024555062575870812152535107633274882125", "6978415864521499843092624111016722859262479622172662553536833301034271706262", "4135208064219040665956576816380326101812041259000783076266688443246751604503", "3170260842944628279187126241517526053484378541795476268362403230613442052402", "4342359007634045612907285413193091075155071579174992137913324882848900239346", "865863211191910612990543945914043484144675745694815540239437037901450625109", "5338245711792133777698393453750146971681819747170395242636501304932379809960", "3971599647525318441413019352449721743960136015973593568651374667343390396180", "6781766165911636738711413118313274719395557174639193685513603627811259323393", "6567640779716870031735217184183741356489258821829157665850681332082834576535", "6191305287335176564696816642287358623642659237049314275921775543604346368066", "6966400339991045274968589508279503115523111941692065146897205830618452544258", "1932855327274373118649578109656632980426924425832054484211124717453633370522", "2422517079429369491095512851537216478826546687856281300427936709663355540147", "1828355802689263445921624588217734691264544626928882494763041934854213400746", "5425169782538910714092423632218831094890099464960756551344981699594055460447", "2326252787767864222978752870209848689412849751880836738068297509804573644232", "2926199112255787778707184107940826811888856500774718781576137388347946365290", "5862428253581911978164236873998992598944144594277149928428395602902613123842"].into_iter().map(|s| s.to_string()).collect(),
                        left_dir: 852258,
                        right_dir: 852259
                    }),
                    "channel_open" => Box::new(ChannelOpenProverWitness{
                        hs: vec![156, 100, 164, 70, 175, 125, 251, 187, 195, 252, 218, 163, 247, 162, 104, 223, 141, 31, 157, 80, 201, 75, 109, 100, 103, 126, 160, 83, 35, 62, 110, 151],
                        h2: vec![199, 19, 121, 24, 40, 28, 157, 126, 161, 31, 209, 97, 176, 243, 199, 25, 167, 27, 254, 231, 67, 165, 171, 4, 6, 254, 217, 126, 251, 196, 209, 246],
                        ch_sh_len: 446,
                        serv_ext_len: 4655,
                        serv_ext_ct_tail: vec![55, 20, 119, 239, 196, 227, 25, 25, 66, 85, 86, 48, 177, 19, 204, 221, 60, 227, 215, 249, 250, 136, 147, 200, 179, 140, 65, 197, 170, 13, 131, 223, 141, 241, 30, 29, 93, 46, 240, 185, 88, 233, 68, 62, 98],
                        serv_ext_tail_len: 45,
                        sha_h_checkpoint: vec![1995366002, 482694727, 3830622027, 387007927, 117988151, 1972788801, 1813956131, 3208532732],
                        comm: "5658669201696800707554988141608320636732262216527181082290336347131007410316".to_string()
                    }),
                    _ => panic!("Unexpected witness variant: {:?}", prover_witness), 
                };

                prover_input_map = prover_witness.to_map().input_map;
            } else {
                panic!("Missing input (--pin or --witness)")
            }
            println!("{:#?}", prover_input_map);

            println!("Spartan Proving");
            let (gens, inst, proof) = spartan::prove(prover_key, &prover_input_map, options.circ.field.builtin).unwrap(); 
            write_to_path::<_, _>(gens_path, &gens).unwrap();  // public parameters
            write_to_path::<_, _>(inst_path, &inst) .unwrap();  // instance
            write_to_path::<_, _>(proof_path, &proof).unwrap();  // proof
        }
        Action::Verify { verifier_key, vin, witness, gens_path, inst_path, proof_path } => {
            let verifier_input_map;  

            if let Some(vin_path) = vin {  
                verifier_input_map = text::parse_value_map(&std::fs::read(vin_path).unwrap());
            } else if let Some(verifier_witness) = witness {
                let verifier_witness: Box<dyn Witness> = match verifier_witness.as_str() {
                    "test" => Box::new(TestVerifierWitness {  // ./examples/ZoKrates/pf/arr_str_arr_str.zok.vin
                        value: "16".to_string()
                    }),
                    "merkle_path_auth" => Box::new(MerklePathAuthVerifierWitness {
                        root: "7600623645497885789568289175286925629407521470620758257549081136559540347639".to_string()
                    }),
                    "non_membership" => Box::new(NonMembershipVerifierWitness {
                        input_domain_name_wildcard: "moc.nozama.".chars().map(|c| (c as u8).to_string()).collect(),
                        root: "5972733345965465510373436926431083918242531555386867859948086370295902707692".to_string(),
                        ret: "1".to_string()
                    }),
                    "channel_open" => Box::new(ChannelOpenVerifierWitness {
                        h2: vec![199, 19, 121, 24, 40, 28, 157, 126, 161, 31, 209, 97, 176, 243, 199, 25, 167, 27, 254, 231, 67, 165, 171, 4, 6, 254, 217, 126, 251, 196, 209, 246],
                        ch_sh_len: 446,
                        serv_ext_len: 4655,
                        serv_ext_ct_tail: vec![55, 20, 119, 239, 196, 227, 25, 25, 66, 85, 86, 48, 177, 19, 204, 221, 60, 227, 215, 249, 250, 136, 147, 200, 179, 140, 65, 197, 170, 13, 131, 223, 141, 241, 30, 29, 93, 46, 240, 185, 88, 233, 68, 62, 98],
                        serv_ext_tail_len: 45,
                        comm: "5658669201696800707554988141608320636732262216527181082290336347131007410316".to_string()
                    }),
                    _ => panic!("Unexpected witness variant: {:?}", verifier_witness), 
                };  

                verifier_input_map = verifier_witness.to_map().input_map;
            } else {
                panic!("Missing input (--pin or --witness)")
            }
            println!("{:#?}", verifier_input_map);

            println!("Spartan Verifying");
            let gens = read_from_path::<_, _>(gens_path).unwrap();
            let inst = read_from_path::<_, _>(inst_path).unwrap();
            let proof = read_from_path::<_, _>(proof_path).unwrap();
            spartan::verify(verifier_key, &verifier_input_map, &gens, &inst, proof).unwrap();
        }
    }
}