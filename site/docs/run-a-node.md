# Run a node

## Watch the testnet

A watcher is what keeps the sequencer honest. Anyone can run one. It needs
only the testnet's genesis file and an Aptos testnet account with a little
APT for the challenge bond.

```sh
git clone https://github.com/MusieTesfaye/SENA && cd SENA
cargo build --release -p sena-node
mkdir -p watch && curl -o watch/genesis.json <the testnet's genesis.json>
aptos init --profile watcher --network testnet       # then fund it
target/release/sena-node watch --data-dir watch \
  --contract <SENA contract on Aptos> --profile watcher --account <its address>
```

It reads every assertion and its data from Aptos, re-executes it, and
challenges any that is wrong, playing the dispute to the end.

## Run your own network

The [deploy kit](https://github.com/MusieTesfaye/SENA/tree/main/deploy) brings
up a full network on one Linux server with one command:

- sequencer, relayer and watcher;
- faucet and identity issuer;
- Google key rotation;
- HTTPS.

It settles on Aptos testnet. The public testnet runs on it, on an Oracle Cloud
free-tier ARM server.

## A local devnet

For development, `bun run devnet` in the wallet repository starts a node and a
faucet on your machine, no Aptos needed. See the
[end-to-end guide](https://github.com/MusieTesfaye/SENA/blob/main/docs/END_TO_END.md).
