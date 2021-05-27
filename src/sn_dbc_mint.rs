// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Basic chat like example that demonstrates how to connect with peers and exchange data.

mod common;

use anyhow::{anyhow, Context, Result, Error};
use bls_dkg::key_gen::{PublicKeySet, SecretKeyShare};
use bytes::Bytes;
use common::{Event, EventReceivers};
use qp2p::{Config, Endpoint, QuicP2p};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use sn_dbc::{Dbc, DbcContent, Hash, Mint, MintRequest, MintTransaction};
use std::collections::{BTreeSet, BTreeMap, HashMap, HashSet};
use std::iter::FromIterator;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use threshold_crypto::{Signature, SignatureShare, SecretKeySet};
use tokio::task::JoinHandle;
use serde::{Serialize, Deserialize};

struct PeerList {
    peers: Vec<SocketAddr>,
}

impl PeerList {
    fn new() -> Self {
        Self { peers: Vec::new() }
    }

    fn insert(&mut self, peer: SocketAddr) {
        if !self.peers.contains(&peer) {
            self.peers.push(peer)
        }
    }

    fn remove(&mut self, peer_idx: usize) -> Result<SocketAddr> {
        if peer_idx < self.peers.len() {
            Ok(self.peers.remove(peer_idx))
        } else {
            Err(anyhow!("Index out of bounds"))
        }
    }

    fn get(&self, peer_idx: usize) -> Option<&SocketAddr> {
        self.peers.get(peer_idx)
    }

    fn list(&self) {
        for (idx, peer) in self.peers.iter().enumerate() {
            println!("{:3}: client:{}", idx, peer);
        }
    }
}

#[derive(Debug)]
struct MintInfo {
    mint: Mint,
    genesis: Dbc,
    genesis_key: bls_dkg::outcome::Outcome,
}

/// This type is just for serializing HashMap<Hash, SignatureShare>
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SignatureShareMap(HashMap<Hash, SignatureShare>);


/// This chat app connects two machines directly without intermediate servers and allows
/// to exchange messages securely. All the messages are end to end encrypted.
#[derive(Debug, StructOpt)]
struct CliArgs {
    #[structopt(flatten)]
    quic_p2p_opts: Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    let CliArgs { quic_p2p_opts } = CliArgs::from_args();

    let qp2p = QuicP2p::with_config(Some(quic_p2p_opts), Default::default(), false)?;
    let (endpoint, incoming_connections, incoming_messages, disconnections) =
        qp2p.new_endpoint().await?;
    let event_rx = EventReceivers {
        incoming_connections,
        incoming_messages,
        disconnections,
    };

    print_logo();
    println!("Type 'help' to get started.");

    let peerlist = Arc::new(Mutex::new(PeerList::new()));
    let _rx_thread = handle_qp2p_events(event_rx, peerlist.clone());

    let mut mintinfo: MintInfo = new_mint(1000);

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
                let mut peerlist = peerlist.lock().unwrap();
                let result = match cmd {
                    "ourinfo" => {
                        print_ourinfo(&endpoint);
                        Ok(())
                    }
                    "addpeer" => {
                        let addr = parse_peer(&args.collect::<Vec<_>>().join(" "))?;
                        endpoint.connect_to(&addr).await?;
                        peerlist.insert(addr);
                        Ok(())
                    }
                    "listpeers" => {
                        peerlist.list();
                        Ok(())
                    }
                    "delpeer" => args
                        .next()
                        .ok_or_else(|| anyhow!("Missing index argument"))
                        .and_then(|idx| idx.parse().map_err(|_| anyhow!("Invalid index argument")))
                        .and_then(|idx| peerlist.remove(idx))
                        .and(Ok(())),
                    "mintinfo" => print_mintinfo(&args.collect::<Vec<_>>().join(" "), &mintinfo),
                    "prepare_tx" => prepare_tx(),
                    "sign_tx" => sign_tx(),
                    "prepare_reissue" => prepare_reissue(),
                    "reissue" => reissue(&mut mintinfo.mint),
                    "reissue_ez" => reissue_ez(&mut mintinfo),
                    "newkey" => newkey(),
                    "decode" => decode_input(),
                    "send" => on_cmd_send(&mut args, &peerlist, &endpoint).await,
                    "quit" | "exit" => break 'outer,
                    "help" => {
                        println!(
//                            "Commands: ourinfo, addpeer, listpeers, delpeer, newkey, mintinfo [dbg], reissue, reissue_ez, send, quit, exit, help"
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

    drop(qp2p);
    // rx_thread.await?;
    Ok(())
}

fn new_mint(amount: u64) -> MintInfo {
    let genesis_key = crate::bls_dkg_id(1);
    let (mint, dbc) = Mint::genesis(genesis_key.public_key_set.clone(), amount);
    MintInfo {
        mint,
        genesis: dbc,
        genesis_key,
    }
}

fn newkey() -> Result<()> {

    let (m, n) = loop {
        let n: usize = readline_prompt("How many key shares (n): ").parse()?;
        let m: usize = readline_prompt("How many shares needed to sign (m): ").parse()?;

        if m == 0 || n == 0 {
            println!("m and n must be greater than 0\n");
            continue;
        }
        if m > n {
            println!("m must be smaller than n\n");
            continue;
        }
        break (m, n);
    };

    let sks = mk_secret_key_set(m-1);

    // let blspair = bls_dkg_id(2);

    // println!("Secret (Reveal):     {}", &blspair.secret_key_share.reveal());
    // println!("Secret (bytes):      {:?}", sk_to_bytes(&blspair.secret_key_share));
    // let b = sk_to_bytes(&blspair.secret_key_share);
    // println!("Secret (from bytes): {:?}", sk_from_bytes(b.as_slice()).reveal());
    // let e = encode(&sk_to_bytes(&blspair.secret_key_share));
    // println!("Secret (decoded):    {:?}", decode(&e).unwrap());
    // println!("Secret (from dec):   {:?}", sk_from_bytes(&decode(&e).unwrap()).reveal());

    println!("\n -- Secret Key Shares --");
    for i in (0..n).into_iter() {
        println!("{}", encode(&sk_to_bytes(&sks.secret_key_share(i))));
    }
    let bytes: Vec<u8> = bincode::serialize(&sks.public_keys()).unwrap();
    println!("\n -- Public Key Set --\n{}\n", encode(&bytes));

/*
    println!(
        "\nSecret: {}",
        encode(&sk_to_bytes(&blspair.secret_key_share))
    );
    let bytes: Vec<u8> = bincode::serialize(&blspair.public_key_set).unwrap();
    println!("Public Set: {}", encode(&bytes));
    println!(
        "Public: {}\n",
        encode(&blspair.public_key_set.public_key().to_bytes())
    );
*/    

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
        "Secret: {}\n",
        encode(&sk_to_bytes(&mintinfo.genesis_key.secret_key_share))
    );
    let bytes: Vec<u8> = bincode::serialize(&mintinfo.genesis_key.public_key_set).unwrap();
    println!("Public Set: {}\n", encode(&bytes));
    println!(
        "Public ED25519: {}\n\n",
        encode(&mintinfo.mint.public_key().to_bytes())
    );

    println!("\n-- Genesis DBC --\n");
    print_dbc_human(&mintinfo.genesis, true);

    println!();

    println!("-- SpendBook --\n");
    for (dbchash, _tx) in mintinfo.mint.spendbook.transactions.iter() {
        println!("  {}", encode(&dbchash));
    }

    println!();

    Ok(())
}

fn print_dbc_human(dbc: &Dbc, outputs: bool) {
    println!("id: {}\n", encode(dbc.name()));
    println!("amount: {}\n", dbc.content.amount);
    println!("output_number: {}\n", dbc.content.output_number);

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
    let bytes = bincode::serialize(&dbc).unwrap();
    println!("{}\n", encode(bytes));
}

fn decode_input() -> Result<()> {
    let t = readline_prompt("\n[d: DBC, t: Transaction, s: SignatureShareMap, r: ReissueRequest\nType: ");
    let input = readline_prompt("\nPaste Data: ");
    let bytes = decode(input).unwrap();

    match t.as_str() {
        "d" => { 
            println!("\n\n-- Start DBC --\n");
            print_dbc_human(&dbc_from_bytes(&bytes), true);
            println!("\n\n-- End DBC --\n");
        },
        "t" => println!("\n\n-- Transaction -- {:#?}", minttx_from_bytes(&bytes)),
        "s" => println!("\n\n-- SignatureShareMap -- {:#?}", ssm_from_bytes(&bytes)),
        "r" => println!("\n\n-- ReissueRequest -- {:#?}", mr_from_bytes(&bytes)),
        _ => println!("Unknown type!"),
    }
    println!();

    Ok(())
}


async fn on_cmd_send<'a>(
    mut args: impl Iterator<Item = &'a str>,
    peer_list: &PeerList,
    endpoint: &Endpoint,
) -> Result<()> {
    let peer = args
        .next()
        .with_context(|| "Missing index argument")
        .and_then(|idx| idx.parse().map_err(|_| anyhow!("Invalid index argument")))
        .and_then(|idx| {
            peer_list
                .get(idx)
                .ok_or_else(|| anyhow!("Index out of bounds"))
        })?;
    let msg = Bytes::from(args.collect::<Vec<_>>().join(" "));
    endpoint.send_message(msg, peer).await.map_err(From::from)
}

fn handle_qp2p_events(
    mut event_rx: EventReceivers,
    peer_list: Arc<Mutex<PeerList>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                Event::ConnectedTo { addr } => peer_list.lock().unwrap().insert(addr),
                Event::NewMessage { src, msg } => {
                    if msg.len() > 512 {
                        println!("[{}] received bytes: {}", src, msg.len());
                    } else {
                        println!(
                            "[{}] {}",
                            src,
                            String::from_utf8(msg.to_vec())
                                .unwrap_or_else(|_| "Invalid String".to_string())
                        );
                    }
                }
            }
        }
    })
}

fn parse_peer(input: &str) -> Result<SocketAddr> {
    parse_socket_addr(&input).map_err(|_| {
        anyhow!("Invalid peer (valid examples: \"1.2.3.4:5678\", \"8.7.6.5:4321\", ...)")
    })
}

fn parse_socket_addr(input: &str) -> Result<SocketAddr> {
    input.parse().map_err(|_| anyhow!("Invalid socket address"))
}

fn print_ourinfo(endpoint: &Endpoint) {
    let ourinfo = endpoint.socket_addr();

    println!("Our info: {}", ourinfo);
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
        let dbc_base64 = readline_prompt("\nInput DBC, or 'done': ");
        let dbc = if dbc_base64 == "done" {
            break;
        } else {
            let bytes = decode(&dbc_base64).unwrap();
            dbc_from_bytes(&bytes)
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
        let line = readline_prompt("Amount, or 'cancel': ");
        let amount: u64 = if line == "cancel" {
            println!("\nprepare_tx cancelled\n");
            break;
        } else {
            line.parse().unwrap()
        };
        if amount > remaining || amount == 0 {
            println!("\nThe amount must be in the range 1..{}\n", remaining);
            continue;
        }

        let line = readline_prompt("\nPublic Key Set, or 'cancel': ");
        let pub_out = if line == "cancel" {
            break;
        } else {
            line
        };

        let pub_out_bytes = decode(&pub_out).unwrap();
        let pub_out_set = pks_from_bytes(pub_out_bytes.as_slice());

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

    let bytes = bincode::serialize(&transaction).unwrap();

    println!("\n-- Transaction (Base64) --");
    println!("{}", encode(&bytes));
    println!("-- End Transaction --\n");

    Ok(())
}

fn sign_tx() -> Result<()> {

    let tx_bytes = decode(readline_prompt("\nTx: ")).unwrap();
    let tx = minttx_from_bytes(&tx_bytes);

    let mut inputs: HashMap<Dbc, SecretKeyShare> = Default::default();

    for (i, dbc) in tx.inputs.iter().enumerate() {
        println!("-----------------");
        println!("Input #{} [id: {}, amount: {}]", i, encode(dbc.name()), dbc.content.amount );
        println!("-----------------");

        let key = readline_prompt("\nSecret Key Share, or 'cancel': ");
        let secret = if key == "cancel" {
            break;
        } else {
            let b64 = decode(&key).unwrap();
            sks_from_bytes(b64.as_slice())
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
    let bytes = bincode::serialize(&sig_shares).unwrap();
    println!("{}", encode(&bytes));
    println!("-- End SignatureShareMap --\n");

    Ok(())
}

fn prepare_reissue() -> Result<()> {

    let tx_bytes = decode(readline_prompt("\nTx: ")).unwrap();
    let tx = minttx_from_bytes(&tx_bytes);
    let mut sig_shares_by_input: HashMap<Hash, BTreeMap<usize, SignatureShare>> = Default::default();

    for dbc in tx.inputs.iter() {
        println!("-----------------");
        println!("Input #{} [id: {}, amount: {}]", dbc.content.output_number, encode(dbc.name()), dbc.content.amount );
        println!("-----------------");

        for _ in (0..dbc.content.owner.threshold() + 1).into_iter() {
            let key = readline_prompt("\nSignatureShareMap, or 'cancel': ");
            let share_map = if key == "cancel" {
                println!("\nprepare_reissue cancelled.\n");
                return Ok(());
            } else {
                let b64 = decode(&key).unwrap();
                ssm_from_bytes(b64.as_slice())
            };
            for (name, share) in share_map.0.iter() {
                let list = sig_shares_by_input.entry(*name).or_insert(BTreeMap::default());
                (*list).insert(list.len(), share.clone());
            }
        }
    }

    let mut proofs: HashMap<Hash, Signature> = Default::default();
    for dbc in tx.inputs.iter() {
        let shares = sig_shares_by_input.get(&dbc.name()).unwrap();
        let sig = dbc.content.owner.combine_signatures(shares).map_err(|e| Error::msg(format!("{}", e)))?;
        proofs.insert(dbc.name(), sig);
    }

    println!("\n\nThank-you.   Preparing Reissue Request...\n\n");

    let mint_request = MintRequest {
        transaction: tx,
        input_ownership_proofs: proofs,
    };

    println!("\n-- Reissue Request (Base64) --");
    let bytes = bincode::serialize(&mint_request).unwrap();
    println!("{}", encode(&bytes));
    println!("-- End Reissue Request --\n");

    Ok(())
}


fn reissue(mint: &mut Mint) -> Result<()> {

    let mr_bytes = decode(readline_prompt("\nReissue Request: ")).unwrap();
    let mint_request = mr_from_bytes(&mr_bytes);

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
        print_dbc_human(dbc, false);
        println!("-- End DBC --\n");
    }

    Ok(())
}


//fn reissue(input: &str, mintinfo: &mut MintInfo) -> Result<()> {
fn reissue_ez(mintinfo: &mut MintInfo) -> Result<()> {
    let mut inputs: HashMap<Dbc, SecretKeyShare> = Default::default();

    loop {
        let dbc_base64 = readline_prompt("\nInput DBC, or 'done': ");
        let dbc = if dbc_base64 == "done" {
            break;
        } else {
            let bytes = decode(&dbc_base64)?;
            dbc_from_bytes(&bytes)
        };

        let key = readline_prompt("\nInput DBC Secret Key, or 'done': ");
        let secret = if key == "done" {
            break;
        } else {
            let b64 = decode(&key)?;
            sks_from_bytes(b64.as_slice())
        };

        inputs.insert(dbc, secret);
    }
    let amounts_input = readline_prompt("\nOutput Amounts: ");
    let pub_out = readline_prompt("\nOutput Public Key Set: ");
    let pub_out_bytes = decode(&pub_out)?;
    let pub_out_set = pks_from_bytes(pub_out_bytes.as_slice());

    let amounts: Vec<u64> = amounts_input
        .split_whitespace()
        .map(|s| s.parse().expect("parse error. invalid amount(s)"))
        .collect();

    println!("\n\nThank-you.   Generating DBC(s)...\n\n");

    //    let amounts = vec![500, 300, 100, 50, 25, 25];
    reissue_ez_worker(mintinfo, inputs, amounts, pub_out_set)
}

fn reissue_ez_worker(
    mintinfo: &mut MintInfo,
    my_inputs: HashMap<Dbc, SecretKeyShare>,
    output_amounts: Vec<u64>,
    out_pubkey: PublicKeySet,
) -> Result<()> {
    //    let output_amounts: Vec<u64> = Vec::from_iter(amounts.into_iter());
    //    let output_amount: u64 = output_amounts.iter().sum();

    //    let inputs = HashSet::from_iter(vec![mintinfo.genesis.clone()]);
    //    let input_hashes = BTreeSet::from_iter(inputs.iter().map(|in_dbc| in_dbc.name()));

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
        let sig = dbc.content.owner.combine_signatures(vec![(0, &sig_share)]).unwrap();
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
        print_dbc_human(dbc, false);
        println!("-- End DBC --\n");
    }

    Ok(())
}

fn mk_secret_key_set(threshold: usize) -> SecretKeySet {
    SecretKeySet::random(threshold, &mut rand::thread_rng())
}

fn bls_dkg_id(num_shares: usize) -> bls_dkg::outcome::Outcome {
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

    let (_, outcome) = key_gen.generate_keys().unwrap();
    outcome
}

fn sk_to_bytes(sk: &SecretKeyShare) -> Vec<u8> {
    use threshold_crypto::serde_impl::SerdeSecret;
    bincode::serialize(&SerdeSecret(&sk)).unwrap()
}

// fn sk_from_bytes(b: &[u8]) -> SecretKey {
//     bincode::deserialize(&b).unwrap()
// }

fn sks_from_bytes(b: &[u8]) -> SecretKeyShare {
    bincode::deserialize(&b).unwrap()
}

fn pks_from_bytes(b: &[u8]) -> PublicKeySet {
    bincode::deserialize(&b).unwrap()
}

fn dbc_from_bytes(b: &[u8]) -> Dbc {
    bincode::deserialize(&b).unwrap()
}

fn mr_from_bytes(b: &[u8]) -> MintRequest {
    bincode::deserialize(&b).unwrap()
}

fn ssm_from_bytes(b: &[u8]) -> SignatureShareMap {
    bincode::deserialize(&b).unwrap()
}


fn minttx_from_bytes(b: &[u8]) -> MintTransaction {
    bincode::deserialize(&b).unwrap()
}


fn readline_prompt(prompt: &str) -> String {
    loop {
        println!("{}", prompt);
        let line = readline();
        if !line.is_empty() {
            return line;
        }
    }
}

fn readline() -> String {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap(); // including '\n'
    line.trim().to_string()
}

fn encode<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(data)
}

fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>> {
    hex::decode(data).map_err(|e| anyhow!(format!("{}", e)))
}

// fn byte_slice_to_array_32(slice: &[u8]) -> [u8; 32] {
//     use std::convert::TryInto;
//     println!("slice: {:#?}", slice);
//     slice.try_into().expect("slice with incorrect length")
// }
