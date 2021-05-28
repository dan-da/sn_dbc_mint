// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Basic chat like example that demonstrates how to connect with peers and exchange data.

use anyhow::{anyhow, Result, Error};
use bls_dkg::key_gen::{PublicKeySet, SecretKeyShare};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use sn_dbc::{Dbc, DbcContent, Hash, Mint, MintRequest, MintTransaction};
use std::collections::{BTreeSet, BTreeMap, HashMap, HashSet};
use std::iter::FromIterator;
use threshold_crypto::{Signature, SignatureShare, SecretKeySet};
use threshold_crypto::poly::Poly;
use serde::{Serialize, Deserialize};
use threshold_crypto::serde_impl::SerdeSecret;

#[derive(Debug)]
struct MintInfo {
    mint: Mint,
    genesis: Dbc,
    genesis_key: bls_dkg::outcome::Outcome,
}

/// This type is just for serializing HashMap<Hash, SignatureShare>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SignatureShareMap(HashMap<Hash, SignatureShare>);


fn main() -> Result<()> {

    print_logo();
    println!("Type 'help' to get started.");

    let mut mintinfo: MintInfo = new_mint(1000)?;

    let mut rl = Editor::<()>::new();
    rl.set_auto_add_history(true);
    'outer: loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let mut args = line.trim().split_whitespace();
                let cmd = if let Some(cmd) = args.next() {
                    cmd
                } else {
                    continue 'outer;
                };
                let result = match cmd {
                    "mintinfo" => print_mintinfo(&args.collect::<Vec<_>>().join(" "), &mintinfo),
                    "prepare_tx" => prepare_tx(),
                    "sign_tx" => sign_tx(),
                    "prepare_reissue" => prepare_reissue(),
                    "reissue" => reissue(&mut mintinfo.mint),
                    "reissue_ez" => reissue_ez(&mut mintinfo),
                    "newkey" => newkey(),
                    "decode" => decode_input(),
                    "quit" | "exit" => break 'outer,
                    "help" => {
                        println!(
                            "Commands: newkey, mintinfo [dbg], reissue, reissue_ez, decode, exit, help"
                        );
                        Ok(())
                    }
                    _ => Err(anyhow!("Unknown command")),
                };
                if let Err(msg) = result {
                    println!("Error: {}", msg);
                }
            }
            Err(ReadlineError::Eof) | Err(ReadlineError::Interrupted) => break 'outer,
            Err(e) => {
                println!("Error reading line: {}", e);
            }
        }
    }

    Ok(())
}

fn new_mint(amount: u64) -> Result<MintInfo> {
    let genesis_key = crate::bls_dkg_id(1)?;
    let (mint, dbc) = Mint::genesis(genesis_key.public_key_set.clone(), amount);
    Ok(MintInfo {
        mint,
        genesis: dbc,
        genesis_key,
    })
}

fn newkey() -> Result<()> {

    let poly_input = readline_prompt("\nPoly of existing SecretKeySet (or 'new' to generate new key): ")?;

    let sks = match poly_input.as_str() {
        "new" => {
            let m = loop {
                let m: usize = readline_prompt("\nHow many shares needed to sign (m in m-of-n): ")?.parse()?;

                if m == 0 {
                    println!("m must be greater than 0\n");
                    continue;
                }
                break m;
            };

            mk_secret_key_set(m-1)
        },
        _ => {
            let poly: Poly = from_be_hex(&poly_input)?;
            // println!("Poly Hex: {}", to_be_hex(&poly)?);
            // println!("Commitment Hex: {}", to_be_hex(&poly.commitment())?);

            SecretKeySet::from(poly)
        }
    };

    println!("\n -- SecretKeyShares --");
    for i in (0..sks.threshold()+5).into_iter() {
        println!("  {}. {}", i, encode(&sks_to_bytes(&sks.secret_key_share(i))?));
    }

    println!("\n -- PublicKeyShares --");
    for i in (0..sks.threshold()+5).into_iter() {
// temporary: the 2nd line matches ian coleman's bls tool output.  but why not the first?        
//        println!("  {}. {}", i, to_be_hex::<PublicKeyShare>(&sks.public_keys().public_key_share(i))?);
        println!("  {}. {}", i, encode(&sks.public_keys().public_key_share(i).to_bytes()));
    }

    println!("\n -- PublicKeySet --\n{}\n", to_be_hex(&sks.public_keys())?);
    
    println!("\nSigning Threshold: {}  ({} signers required)\n", sks.threshold(), sks.threshold()+1);

    Ok(())
}

fn print_mintinfo(args: &str, mintinfo: &MintInfo) -> Result<()> {
    match args == "dbg" {
        true => print_mintinfo_debug(mintinfo),
        false => print_mintinfo_human(mintinfo),
    }
}

fn print_mintinfo_debug(mintinfo: &MintInfo) -> Result<()> {
    println!("\n{:#?}\n", mintinfo);
    Ok(())
}

fn print_mintinfo_human(mintinfo: &MintInfo) -> Result<()> {
    println!();

    println!("-- Mint Keys --\n");
    println!(
        "SecretKeyShare: {}\n",
        encode(&sks_to_bytes(&mintinfo.genesis_key.secret_key_share)?)
    );
    println!("PublicKeySet: {}\n", to_be_hex(&mintinfo.genesis_key.public_key_set)?);

    println!("\n-- Genesis DBC --\n");
    print_dbc_human(&mintinfo.genesis, true)?;

    println!();

    println!("-- SpendBook --\n");
    for (dbchash, _tx) in mintinfo.mint.spendbook.transactions.iter() {
        println!("  {}", encode(&dbchash));
    }

    println!();

    Ok(())
}

fn print_dbc_human(dbc: &Dbc, outputs: bool) -> Result<()> {
    println!("id: {}\n", encode(dbc.name()));
    println!("amount: {}\n", dbc.content.amount);
    println!("output_number: {}\n", dbc.content.output_number);
    println!("owner: {}\n", to_be_hex(&dbc.content.owner)?);

    // dbc.content.parents and dbc.transaction.inputs seem to be the same
    // so for now we are just displaying the latter.
    // println!("parents:");
    // for p in &dbc.content.parents {
    //     println!("  {}", encode(p))
    // }

    println!("inputs:");
    for i in &dbc.transaction.inputs {
        println!("  {}", encode(i))
    }

    if outputs {
        println!("\noutputs:");
        for i in &dbc.transaction.outputs {
            println!("  {}", encode(i))
        }
    }

    println!("\nData:");
    println!("{}\n", to_be_hex(&dbc)?);
    Ok(())
}

fn decode_input() -> Result<()> {
    let t = readline_prompt("\n[d: DBC, t: Transaction, s: SignatureShareMap, r: ReissueRequest, pks: PublicKeySet, sks: SecretKeySet]\nType: ")?;
    let input = readline_prompt("\nPaste Data: ")?;
    let bytes = decode(input)?;

    match t.as_str() {
        "d" => { 
            println!("\n\n-- Start DBC --\n");
            print_dbc_human(&from_be_bytes(&bytes)?, true)?;
            println!("\n\n-- End DBC --\n");
        },
        "pks" => { 
            let pks: PublicKeySet = from_be_bytes(&bytes)?;
            println!("\n\n-- Start PublicKeySet --");
            println!("threshold: {} ({} signature shares required)\n", pks.threshold(), pks.threshold()+1);
            println!("public_key: {}", encode(&pks.public_key().to_bytes()));
// temporary: the 2nd line matches ian coleman's bls tool output.  but why not the first?
//            println!("PublicKeyShare[0]: {}", to_be_hex(&pks.public_key_share(0))? );
            println!("PublicKeyShare[0]: {}", encode(&pks.public_key_share(0).to_bytes()) );
            println!("-- End PublicKeySet --\n");
        },
        "sks" => { 
            let poly: Poly = from_be_bytes(&bytes)?;
            let sks = SecretKeySet::from(poly);
            println!("\n\n-- Start SecretKeySet --");
            println!("threshold: {} ({} signature shares required)\n", sks.threshold(), sks.threshold()+1);
            println!("SecretKeyShare[0]: {}", encode(sks_to_bytes(&sks.secret_key_share(0))?) );
            println!("-- End SecretKeySet --\n");
        },
        "t" => println!("\n\n-- Transaction -- {:#?}", from_be_bytes::<MintTransaction>(&bytes)?),
        "s" => println!("\n\n-- SignatureShareMap -- {:#?}", from_be_bytes::<SignatureShareMap>(&bytes)?),
        "r" => println!("\n\n-- ReissueRequest -- {:#?}", from_be_bytes::<MintRequest>(&bytes)?),
        _ => println!("Unknown type!"),
    }
    println!();

    Ok(())
}

fn print_logo() {
    println!(
        r#"
 __     _                        
(_  _._|__  |\ | __|_     _ ._|  
__)(_| |(/_ | \|(/_|_\/\/(_)| |< 
 ____  ____   ____   __  __ _       _   
|  _ \| __ ) / ___| |  \/  (_)_ __ | |_ 
| | | |  _ \| |     | |\/| | | '_ \| __|
| |_| | |_) | |___  | |  | | | | | | |_ 
|____/|____/ \____| |_|  |_|_|_| |_|\__|        
  "#
    );
}

fn prepare_tx() -> Result<()> {
    let mut inputs: HashSet<Dbc> = Default::default();

    let mut inputs_total: u64 = 0;
    loop {
        let dbc_base64 = readline_prompt("\nInput DBC, or 'done': ")?;
        let dbc: Dbc = if dbc_base64 == "done" {
            break;
        } else {
            from_be_hex(&dbc_base64)?
        };

        inputs_total += dbc.content.amount;
        inputs.insert(dbc);
    }

    let input_hashes = BTreeSet::from_iter(inputs.iter().map(|e| e.name()));
    let mut i = 0u8;
    let mut outputs: HashSet<DbcContent> = Default::default();

    let mut outputs_total = 0u64;
    while inputs_total - outputs_total != 0 {
        println!();
        println!("------------");
        println!("Output #{}", i);
        println!("------------\n");

        let remaining = inputs_total - outputs_total;
        println!("Inputs total: {}.  Remaining: {}", inputs_total, remaining );
        let line = readline_prompt("Amount, or 'cancel': ")?;
        let amount: u64 = if line == "cancel" {
            println!("\nprepare_tx cancelled\n");
            break;
        } else {
            line.parse()?
        };
        if amount > remaining || amount == 0 {
            println!("\nThe amount must be in the range 1..{}\n", remaining);
            continue;
        }

        let line = readline_prompt("\nPublicKeySet, or 'cancel': ")?;
        let pub_out = if line == "cancel" {
            break;
        } else {
            line
        };

        let pub_out_set: PublicKeySet = from_be_hex(&pub_out)?;

        outputs.insert(
            DbcContent {
                parents: input_hashes.clone(),
                amount,
                output_number: i as u8,
                owner: pub_out_set,
            }
        );
        outputs_total += amount;
        i += 1;
    }

    if outputs.is_empty() {
        println!("\n\nNo outputs specified.  Cancelling.\n\n");
        return Ok(());
    }
    if inputs_total - outputs_total != 0 {
        println!("\n\nInput DBC(s) not fully spent. Cancelling.\n\n");
        return Ok(());
    }

    println!("\n\nThank-you.   Preparing Tx...\n\n");

    let transaction = MintTransaction { inputs, outputs };

    println!("\n-- Transaction (Base64) --");
    println!("{}", to_be_hex(&transaction)?);
    println!("-- End Transaction --\n");

    Ok(())
}

fn sign_tx() -> Result<()> {

    let tx_input = readline_prompt("\nMintTransaction: ")?;
    let tx: MintTransaction = from_be_hex(&tx_input)?;

    let mut inputs: HashMap<Dbc, SecretKeyShare> = Default::default();

    for (i, dbc) in tx.inputs.iter().enumerate() {
        println!("-----------------");
        println!("Input #{} [id: {}, amount: {}]", i, encode(dbc.name()), dbc.content.amount );
        println!("-----------------");

        let key = readline_prompt("\nSecretKeyShare, or 'cancel': ")?;
        let secret: SecretKeyShare = if key == "cancel" {
            break;
        } else {
            from_be_hex(&key)?
        };

        inputs.insert(dbc.clone(), secret);
    }

    println!("\n\nThank-you.   Preparing Signature...\n\n");

    let mut sig_shares: SignatureShareMap = Default::default();
    for (dbc, secret) in inputs.iter() {
        let sig_share = secret.sign(&tx.blinded().hash());
        sig_shares.0.insert(dbc.name(), sig_share);
    }

    println!("\n-- SignatureShareMap (Base64) --");
    println!("{}", to_be_hex(&sig_shares)?);
    println!("-- End SignatureShareMap --\n");

    Ok(())
}

fn prepare_reissue() -> Result<()> {

    let tx_input = readline_prompt("\nMintTransaction: ")?;
    let tx: MintTransaction = from_be_hex(&tx_input)?;
    let mut sig_shares_by_input: HashMap<Hash, BTreeMap<usize, SignatureShare>> = Default::default();

    for dbc in tx.inputs.iter() {
        println!("-----------------");
        println!("Input #{} [id: {}, amount: {}]", dbc.content.output_number, encode(dbc.name()), dbc.content.amount );
        println!("-----------------");

        for _ in (0..dbc.content.owner.threshold() + 1).into_iter() {
            let ssm_input = readline_prompt("\nSignatureShareMap, or 'cancel': ")?;
            let share_map: SignatureShareMap = if ssm_input == "cancel" {
                println!("\nprepare_reissue cancelled.\n");
                return Ok(());
            } else {
                from_be_hex(&ssm_input)?
            };
            for (name, share) in share_map.0.iter() {
                let list = sig_shares_by_input.entry(*name).or_insert(BTreeMap::default());
                (*list).insert(list.len(), share.clone());
            }
        }
    }

    let mut proofs: HashMap<Hash, Signature> = Default::default();
    for dbc in tx.inputs.iter() {
        let shares = match sig_shares_by_input.get(&dbc.name()) {
            Some(s) => s,
            None => return Err(anyhow!("Signature Shares not found for input Dbc {}", encode(&dbc.name()))),
        };
        let sig = dbc.content.owner.combine_signatures(shares).map_err(|e| Error::msg(format!("{}", e)))?;
        proofs.insert(dbc.name(), sig);
    }

    println!("\n\nThank-you.   Preparing Reissue Request...\n\n");

    let mint_request = MintRequest {
        transaction: tx,
        input_ownership_proofs: proofs,
    };

    println!("\n-- MintRequest (Base64) --");    
    println!("{}", to_be_hex(&mint_request)?);
    println!("-- End MintRequest --\n");

    Ok(())
}


fn reissue(mint: &mut Mint) -> Result<()> {

    let mr_input = readline_prompt("\nMintRequest: ")?;
    let mint_request: MintRequest = from_be_hex(&mr_input)?;

    let input_hashes = BTreeSet::from_iter(mint_request.transaction.inputs.iter().map(|e| e.name()));

    let (transaction, transaction_sigs) =
        mint.reissue(mint_request.clone(), input_hashes)?;

    // Verify transaction returned to us by the Mint matches our request
    assert_eq!(mint_request.transaction.blinded(), transaction);

    // Verify signatures corespond to each input
    let (pubkey, sig) = transaction_sigs.values().cloned().next().unwrap();
    for input in mint_request.transaction.inputs.iter() {
        assert_eq!(transaction_sigs.get(&input.name()), Some(&(pubkey, sig)));
    }
    assert_eq!(transaction_sigs.len(), transaction.inputs.len());

    let mut output_dbcs = Vec::from_iter(mint_request.transaction.outputs.into_iter().map(
        |content| Dbc {
            content,
            transaction: transaction.clone(),
            transaction_sigs: transaction_sigs.clone(),
        },
    ));

    // sort outputs by output_number
    output_dbcs.sort_by_key(|d| d.content.output_number);

    for dbc in output_dbcs.iter() {
        println!("\n-- Begin DBC --");
        print_dbc_human(dbc, false)?;
        println!("-- End DBC --\n");
    }

    Ok(())
}


//fn reissue(input: &str, mintinfo: &mut MintInfo) -> Result<()> {
fn reissue_ez(mintinfo: &mut MintInfo) -> Result<()> {
    let mut inputs: HashMap<Dbc, SecretKeyShare> = Default::default();

    loop {
        let dbc_input = readline_prompt("\nInput DBC, or 'done': ")?;
        let dbc: Dbc = if dbc_input == "done" {
            break;
        } else {
            from_be_hex(&dbc_input)?
        };

        let key = readline_prompt("\nInput DBC SecretKeyShare, or 'done': ")?;
        let secret = if key == "done" {
            break;
        } else {
            from_be_hex(&key)?
        };

        inputs.insert(dbc, secret);
    }
    let amounts_input = readline_prompt("\nOutput Amounts: ")?;
    let pks_input = readline_prompt("\nOutput PublicKeySet: ")?;
    let pub_out_set: PublicKeySet = from_be_hex(&pks_input)?;

    let amounts: Vec<u64> = amounts_input
        .split_whitespace()
        .map(|s| s.parse().expect("parse error. invalid amount(s)"))
        .collect();

    println!("\n\nThank-you.   Generating DBC(s)...\n\n");

    reissue_ez_worker(mintinfo, inputs, amounts, pub_out_set)
}

fn reissue_ez_worker(
    mintinfo: &mut MintInfo,
    my_inputs: HashMap<Dbc, SecretKeyShare>,
    output_amounts: Vec<u64>,
    out_pubkey: PublicKeySet,
) -> Result<()> {
 
    let inputs = HashSet::from_iter(my_inputs.keys().cloned());
    let input_hashes = BTreeSet::from_iter(my_inputs.keys().map(|e| e.name()));

    // let output_owner = mintinfo.genesis_key.clone();  // todo: accept output pub key set.
    let outputs = output_amounts
        .iter()
        .enumerate()
        .map(|(i, amount)| DbcContent {
            parents: input_hashes.clone(),
            amount: *amount,
            output_number: i as u8,
            //            owner: output_owner.public_key_set.clone(),
            owner: out_pubkey.clone(),
        })
        .collect();

    let transaction = MintTransaction { inputs, outputs };

    let mut proofs: HashMap<Hash, Signature> = Default::default();
    for (dbc, secret) in my_inputs.iter() {
        let sig_share = secret.sign(&transaction.blinded().hash());
        let sig = dbc.content.owner.combine_signatures(vec![(0, &sig_share)]).map_err(|e| anyhow!("{}", e))?;
        proofs.insert(dbc.name(), sig);
    }

    // note:  PublicKeySet tells us how many sigs we need.
    // prepare_tx -> tx                                          // client
    // sign_tx (tx, secret_key_share) -> sig_share               //
    // reissue (tx, [sig share])

    let mint_request = MintRequest {
        transaction,
        //        input_ownership_proofs: HashMap::from_iter(vec![(mintinfo.genesis.name(), sig)]),
        input_ownership_proofs: proofs,
    };

    let (transaction, transaction_sigs) =
        mintinfo.mint.reissue(mint_request.clone(), input_hashes)?;

    // Verify transaction returned to us by the Mint matches our request
    assert_eq!(mint_request.transaction.blinded(), transaction);

    // Verify signatures corespond to each input
    let (pubkey, sig) = transaction_sigs.values().cloned().next().unwrap();
    for input in mint_request.transaction.inputs.iter() {
        assert_eq!(transaction_sigs.get(&input.name()), Some(&(pubkey, sig)));
    }
    assert_eq!(transaction_sigs.len(), transaction.inputs.len());

    let mut output_dbcs = Vec::from_iter(mint_request.transaction.outputs.into_iter().map(
        |content| Dbc {
            content,
            transaction: transaction.clone(),
            transaction_sigs: transaction_sigs.clone(),
        },
    ));

    // sort outputs by output_number
    output_dbcs.sort_by_key(|d| d.content.output_number);

    for dbc in output_dbcs.iter() {
        println!("\n-- Begin DBC --");
        print_dbc_human(dbc, false)?;
        println!("-- End DBC --\n");
    }

    Ok(())
}

fn mk_secret_key_set(threshold: usize) -> SecretKeySet {
    SecretKeySet::random(threshold, &mut rand::thread_rng())
}

fn bls_dkg_id(num_shares: usize) -> Result<bls_dkg::outcome::Outcome> {
    let owner_names: Vec<xor_name::XorName> = (0..num_shares).into_iter().map(|_| rand::random()).collect();
    let threshold = num_shares - 1;
    let (mut key_gen, proposal) = match bls_dkg::KeyGen::initialize(
        owner_names[0],
        threshold,
        BTreeSet::from_iter(owner_names),
    ) {
        Ok(key_gen_init) => key_gen_init,
        Err(e) => panic!("Failed to init key gen {:?}", e),
    };

    let mut msgs = vec![proposal];
    while let Some(msg) = msgs.pop() {
        match key_gen.handle_message(&mut rand::thread_rng(), msg) {
            Ok(response_msgs) => msgs.extend(response_msgs),
            Err(e) => panic!("Error while generating BLS key: {:?}", e),
        }
    }

    let result = match key_gen.generate_keys() {
        Some((_, outcome)) => Ok(outcome),
        None => Err(anyhow!("Key generation failed")),
    };
    result
}

fn sks_to_bytes(sk: &SecretKeyShare) -> Result<Vec<u8>> {
    bincode::serialize(&SerdeSecret(&sk))
        .map(|bytes| bincode_bytes_to_big_endian_bytes(bytes))
        .map_err(|e| anyhow!("{}", e))
}

fn to_be_bytes<T: Serialize>(sk: &T) -> Result<Vec<u8>> {
    bincode::serialize(&sk)
        .map(|bytes| bincode_bytes_to_big_endian_bytes(bytes))
        .map_err(|e| anyhow!("{}", e))
}

fn to_be_hex<T: Serialize>(sk: &T) -> Result<String> {
    Ok(encode(to_be_bytes(sk)?))
}

fn from_be_bytes<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T> {
    let bb = big_endian_bytes_to_bincode_bytes(b.to_vec());
    bincode::deserialize(&bb).map_err(|e| anyhow!("{}", e))
}

fn from_be_hex<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
    Ok(from_be_bytes(&decode(s)?)?)
}

fn readline_prompt(prompt: &str) -> Result<String> {
    loop {
        println!("{}", prompt);
        let line = readline()?;
        if !line.is_empty() {
            return Ok(line);
        }
    }
}

fn readline() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?; // including '\n'
    Ok(line.trim().to_string())
}

fn encode<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(data)
}

fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>> {
    hex::decode(data).map_err(|e| anyhow!(format!("{}", e)))
}


// borrowed from: https://github.com/iancoleman/threshold_crypto_ui/blob/master/src/lib.rs
//
// bincode is little endian encoding, see
// https://docs.rs/bincode/1.3.2/bincode/config/trait.Options.html#options
// but SecretKey.reveal() gives big endian hex
// and all other bls implementations specify bigendian.
// Also see
// https://safenetforum.org/t/simple-web-based-tool-for-bls-keys/32339/37
// so to deserialize a big endian bytes using bincode
// we must convert to little endian bytes
fn big_endian_bytes_to_bincode_bytes(beb: Vec<u8>) -> Vec<u8> {
    let mut bb = beb.clone();
    bb.reverse();
    bb
}

fn bincode_bytes_to_big_endian_bytes(bb: Vec<u8>) -> Vec<u8> {
    let mut beb = bb.clone();
    beb.reverse();
    beb
}

