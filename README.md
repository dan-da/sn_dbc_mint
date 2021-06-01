# sn_dbc_mint

[MaidSafe website](http://maidsafe.net) | [Safe Network Forum](https://safenetforum.org/)
:-------------------------------------: | :---------------------------------------------:

## About

This crate implements a minimal P2P DBC Mint, built on sn_dbc, with an interactive CLI
interface.  Sort of a playground for DBCs and BLS keys.  It implements both server (mint)
and client functionality in a single process.

A design goal is to be interoperable with Ian Coleman's web BLS tool/playground at:
https://iancoleman.io/threshold_crypto_ui/

Presently, SecretKeySet and PublicKeySet generated on the web tool can be used with sn_dbc_mint
and generated SecretKeyShare and PublicKeyShare match up.

Key components are:
* [sn_dbc](https://github.com/maidsafe/sn_dbc/) - Safe Network DBC library
* [threshold_crypto](https://github.com/poanetwork/threshold_crypto) - BLS key library


## Building

On ubuntu:

```
$ sudo apt install build-essential
$ sudo apt install pkg-config
$ cargo build
```

## Running

```
$ cargo run
```

Use the `help` command for a list of available commands.

For a simple guided reissue, use the `reissue_ez` command.

Alternatively, a manual reissue will use these commands in order.

`prepare_tx` --> `sign_tx` --> `prepare_reissue` --> `reissue`

## Usage Examples

* [reissue_ez](./doc/examples/reissue_ez.txt)
* [reissue_manual](./doc/examples/reissue_manual.txt)
* [newkey](./doc/examples/newkey.txt)
* [newmint](./doc/examples/newmint.txt)
* [validate](./doc/examples/validate.txt)
* [decode](./doc/examples/decode.txt)

## License

This Safe Network software is dual-licensed under the Modified BSD (<LICENSE-BSD> <https://opensource.org/licenses/BSD-3-Clause>) or the MIT license (<LICENSE-MIT> <https://opensource.org/licenses/MIT>) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
