# sn_dbc_mint

[MaidSafe website](http://maidsafe.net) | [Safe Network Forum](https://safenetforum.org/)
:-------------------------------------: | :---------------------------------------------:

## About

This crate attempts to implement a P2P DBC Mint, built on sn_dbc.  This is work-in-progress research and nowhere near ready for any real use.

Key components are:
* [sn_dbc](https://github.com/maidsafe/sn_dbc/) - Safe Network DBC library
* [qp2p](https://github.com/maidsafe/qp2p/) - Quic protocol P2P library

## Building

On ubuntu:

```
$ sudo apt install build-essential
$ sudo apt install pkg-config
$ cargo build
```

## Running

```
$ cargo run -- --local-ip <ip> --local-port<port>
```

Note that if local IP matches the public IP then --external-ip and --external-port can be omitted.

Port can be any number, but make sure your firewall is not blocking incoming UDP packets.


Use the `help` command for a list of available commands.


## License

This Safe Network software is dual-licensed under the Modified BSD (<LICENSE-BSD> <https://opensource.org/licenses/BSD-3-Clause>) or the MIT license (<LICENSE-MIT> <https://opensource.org/licenses/MIT>) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
