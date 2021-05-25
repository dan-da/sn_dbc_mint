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

use anyhow::{anyhow, Context, Result};
use bls_dkg::key_gen::{PublicKeySet, SecretKeyShare};
use bytes::Bytes;
use common::{Event, EventReceivers};
use qp2p::{Config, Endpoint, QuicP2p};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use sn_dbc::{Dbc, DbcContent, Hash, Mint, MintRequest, MintTransaction};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use threshold_crypto::Signature;
use tokio::task::JoinHandle;

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
                    "reissue" => reissue(&mut mintinfo),
                    "newkey" => newkey(),
                    "send" => on_cmd_send(&mut args, &peerlist, &endpoint).await,
                    "quit" | "exit" => break 'outer,
                    "help" => {
                        println!(
//                            "Commands: ourinfo, addpeer, listpeers, delpeer, newkey, mintinfo [dbg], reissue, send, quit, exit, help"
                            "Commands: newkey, mintinfo [dbg], reissue, exit, help"
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
    let genesis_key = crate::bls_dkg_id();
    let (mint, dbc) = Mint::genesis(genesis_key.public_key_set.clone(), amount);
    MintInfo {
        mint,
        genesis: dbc,
        genesis_key,
    }
}

fn newkey() -> Result<()> {
    let blspair = bls_dkg_id();

    // println!("Secret (Reveal):     {}", &blspair.secret_key_share.reveal());
    // println!("Secret (bytes):      {:?}", sk_to_bytes(&blspair.secret_key_share));
    // let b = sk_to_bytes(&blspair.secret_key_share);
    // println!("Secret (from bytes): {:?}", sk_from_bytes(b.as_slice()).reveal());
    // let e = base64::encode(&sk_to_bytes(&blspair.secret_key_share));
    // println!("Secret (decoded):    {:?}", base64::decode(&e).unwrap());
    // println!("Secret (from dec):   {:?}", sk_from_bytes(&base64::decode(&e).unwrap()).reveal());

    println!(
        "\nSecret: {}",
        base64::encode(&sk_to_bytes(&blspair.secret_key_share))
    );
    let bytes: Vec<u8> = bincode::serialize(&blspair.public_key_set).unwrap();
    println!("Public Set: {}", base64::encode(&bytes));
    println!(
        "Public: {}\n",
        base64::encode(&blspair.public_key_set.public_key().to_bytes())
    );

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
        base64::encode(&sk_to_bytes(&mintinfo.genesis_key.secret_key_share))
    );
    let bytes: Vec<u8> = bincode::serialize(&mintinfo.genesis_key.public_key_set).unwrap();
    println!("Public Set: {}\n", base64::encode(&bytes));
    println!(
        "Public ED25519: {}\n\n",
        base64::encode(&mintinfo.mint.public_key().to_bytes())
    );

    println!("\n-- Genesis DBC --\n");
    print_dbc_human(&mintinfo.genesis, true);

    println!();

    println!("-- SpendBook --\n");
    for (dbchash, _tx) in mintinfo.mint.spendbook.transactions.iter() {
        println!("  {}", base64::encode(&dbchash));
    }

    println!();

    Ok(())
}

fn print_dbc_human(dbc: &Dbc, outputs: bool) {
    println!("id: {}\n", base64::encode(dbc.name()));
    println!("amount: {}\n", dbc.content.amount);
    println!("output_number: {}\n", dbc.content.output_number);

    // dbc.content.parents and dbc.transaction.inputs seem to be the same
    // so for now we are just displaying the latter.
    // println!("parents:");
    // for p in &dbc.content.parents {
    //     println!("  {}", base64::encode(p))
    // }

    println!("inputs:");
    for i in &dbc.transaction.inputs {
        println!("  {}", base64::encode(i))
    }

    if outputs {
        println!("\noutputs:");
        for i in &dbc.transaction.outputs {
            println!("  {}", base64::encode(i))
        }
    }

    println!("\nData:");
    let bytes = bincode::serialize(&dbc).unwrap();
    println!("{}\n", base64::encode(bytes));
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

//fn reissue(input: &str, mintinfo: &mut MintInfo) -> Result<()> {
fn reissue(mintinfo: &mut MintInfo) -> Result<()> {
    let mut inputs: HashMap<Dbc, (SecretKeyShare, PublicKeySet)> = Default::default();

    loop {
        let dbc_base64 = readline_prompt("\nInput DBC, or 'done': ");
        let dbc = if dbc_base64 == "done" {
            break;
        } else {
            let bytes = base64::decode(&dbc_base64).unwrap();
            dbc_from_bytes(&bytes)
        };

        let key = readline_prompt("\nInput DBC Secret Key, or 'done': ");
        let secret = if key == "done" {
            break;
        } else {
            let b64 = base64::decode(&key).unwrap();
            sks_from_bytes(b64.as_slice())
        };

        let pkey = readline_prompt("\nInput DBC Public Key Set, or 'done': ");
        let pubset = if key == "done" {
            break;
        } else {
            let pb64 = base64::decode(&pkey).unwrap();
            pks_from_bytes(pb64.as_slice())
        };

        inputs.insert(dbc, (secret, pubset));
    }
    let amounts_input = readline_prompt("\nOutput Amounts: ");
    let pub_out = readline_prompt("\nOutput Public Key Set: ");
    let pub_out_bytes = base64::decode(&pub_out).unwrap();
    let pub_out_set = pks_from_bytes(pub_out_bytes.as_slice());

    let amounts: Vec<u64> = amounts_input
        .split_whitespace()
        .map(|s| s.parse().expect("parse error. invalid amount(s)"))
        .collect();

    println!("\n\nThank-you.   Generating DBC(s)...\n\n");

    //    let amounts = vec![500, 300, 100, 50, 25, 25];
    reissue_worker(mintinfo, inputs, amounts, pub_out_set)
}

fn reissue_worker(
    mintinfo: &mut MintInfo,
    my_inputs: HashMap<Dbc, (SecretKeyShare, PublicKeySet)>,
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
    for (dbc, (secret, pubset)) in my_inputs.iter() {
        let sig_share = secret.sign(&transaction.blinded().hash());
        let sig = pubset.combine_signatures(vec![(0, &sig_share)]).unwrap();
        proofs.insert(dbc.name(), sig);
    }

    /*
        let sig_share = genesis_owner
            .secret_key_share
            .sign(&transaction.blinded().hash());

        let sig = genesis_owner
            .public_key_set
            .combine_signatures(vec![(0, &sig_share)])
            .unwrap();
    */
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

fn bls_dkg_id() -> bls_dkg::outcome::Outcome {
    let owner_name = rand::random();
    let threshold = 0;
    let (mut key_gen, proposal) = match bls_dkg::KeyGen::initialize(
        owner_name,
        threshold,
        BTreeSet::from_iter(vec![owner_name]),
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

// fn byte_slice_to_array_32(slice: &[u8]) -> [u8; 32] {
//     use std::convert::TryInto;
//     println!("slice: {:#?}", slice);
//     slice.try_into().expect("slice with incorrect length")
// }
