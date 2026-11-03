# Deploying the SENA testnet

One server runs the whole public testnet:

| Service | What it does | Public at |
|---|---|---|
| `node` | the L2 sequencer and its JSON-RPC | `https://rpc.<host>` |
| `relayer` | posts every block to Aptos testnet, bonded; defends disputes | — |
| `watcher` | re-executes every posted block from Aptos and challenges a wrong one | — |
| `jwk-sync` | accepts Google's new signing keys when Google rotates them | — |
| `faucet` | hands out test USDC, USDT, EURC and DAI, rate-limited | `https://faucet.<host>` |
| `issuer` | verifies emails, phones and usernames; optional | `https://issuer.<host>` |
| `caddy` | HTTPS for all of the above, with automatic certificates | ports 80, 443 |

`<host>` is a free [sslip.io](https://sslip.io) name built from the
server's IP, such as `129-146-20-31.sslip.io`, unless you set `SENA_HOST` to a
domain of your own.

## Or: run it on your own computer

The same kit runs on a Windows, macOS or Linux PC. It settles on the real
Aptos testnet either way.

| Mode | Command | Reachable at |
|---|---|---|
| Local | `deploy/setup.sh --local` | `http://127.0.0.1:8545` (node), `:3001` (faucet), `:3002` (issuer); this PC only |
| Tunnel | `deploy/setup.sh --tunnel <domain>` | `https://<domain>/` (wallet), `/rpc`, `/faucet`, `/issuer`, through ngrok or cloudflared |

Tunnel mode builds the web wallet for the domain and serves it with the chain,
behind one HTTPS name. Caddy listens on `127.0.0.1:8088` for the tunnel. The
client's IP for rate limiting is taken from the tunnel's `X-Forwarded-For`,
rightmost first, so a client cannot forge its way past the faucet's limits.

**On Windows**, use WSL 2:

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
   with the WSL 2 backend.
2. In an administrator PowerShell, run `wsl --install -d Ubuntu-24.04`, then
   restart.
3. In Docker Desktop, open *Settings → Resources → WSL integration* and turn
   on Ubuntu-24.04.
4. Open the Ubuntu terminal. Clone both repositories into your Linux home
   folder (`~`), not `/mnt/c`, which is much slower:

   ```sh
   git clone -b claude/exciting-ritchie-8g61na https://github.com/MusieTesfaye/SENA
   git clone https://github.com/MusieTesfaye/wallet
   echo "VITE_GOOGLE_CLIENT_ID=<your client id>" > wallet/.env
   SENA/deploy/setup.sh --tunnel <your-domain>.ngrok-free.app
   ```

**With ngrok:**

1. Sign up at [ngrok.com](https://ngrok.com).
2. Claim your free static domain under *Domains*.
3. Install the agent and run `ngrok config add-authtoken <token>`.
4. After `setup.sh`, run `ngrok http 8088 --url https://<your-domain>`.

The first time a browser opens the domain, ngrok's free plan shows a warning
page; click *Visit Site*. The free plan also caps monthly requests and
bandwidth. The wallet built for a tunnel refreshes every 5 seconds to save
them, and ngrok's dashboard shows your usage.

Add `https://<your-domain>` to your Google OAuth client as an authorised
JavaScript origin, and `https://<your-domain>/` as a redirect URI.

A PC is a test bed, not a server. While it sleeps, the relayer stops posting
blocks to Aptos, and a block more than an hour old can no longer be posted.
Keep it awake while you use it.

## 1. Create the server (Oracle Cloud free tier)

1. **Compute → Instances → Create instance.**
   - Image: **Canonical Ubuntu 24.04** (or 22.04).
   - Shape: **Ampere VM.Standard.A1.Flex**, 2 OCPUs and 12 GB. That's ample:
     the node uses well under 1 GB.
   - Boot volume: the default 47 GB is enough.
   - Add your SSH public key.
2. **Open ports 80 and 443** in the cloud firewall. In the instance page:
   *Subnet → Security List → Add Ingress Rules*. Add two rules with source
   `0.0.0.0/0`, protocol TCP, destination ports `80` and `443`.
   (`setup.sh` opens them in the machine's own firewall too, which Oracle's
   Ubuntu images also lock down.)
3. SSH in: `ssh ubuntu@<public-ip>`.

## 2. Run the setup

```sh
git clone -b claude/exciting-ritchie-8g61na https://github.com/MusieTesfaye/SENA   # main, once merged
cd SENA
deploy/setup.sh
```

The first run takes about 15 minutes, most of it compiling the node. Then it
stops to wait for money:

```
proposer   0x8e25…1269  (publishes the contracts and posts blocks)
challenger 0x2619…9098  (the watcher)
waiting for testnet APT: proposer has 0.00 APT of 4.00 APT, challenger 0.00 APT of 0.30 APT
```

**Fund both addresses with testnet APT.** Testnet APT is free and worth
nothing:

- The [Aptos testnet faucet](https://aptos.dev/network/faucet): sign in, paste
  an address, and mint. Repeat until the proposer has 4 APT.
- Or send testnet APT from a wallet such as Petra, switched to Testnet.

The script notices within 30 seconds. It then:
- creates the L2 keys and genesis;
- publishes the SENA contracts to Aptos (about 2.3 APT);
- initialises them;
- starts everything.

It ends by printing the network's details and the settings for Vercel. They're
also saved in `deploy/data/testnet.json`.

Check it from anywhere:

```sh
curl -s https://rpc.<host> -d '{"method":"sena_getChainInfo"}'
```

The first request can take a few seconds while Caddy fetches the certificate.

## 3. Turn on identities (optional)

The issuer lets people link an email, phone or username. Give it the
providers you have credentials for:

```sh
mkdir -p deploy/data/issuer
cp ../wallet/issuer.config.example.json deploy/data/issuer/issuer.config.json
nano deploy/data/issuer/issuer.config.json    # keep the providers you will use
nano deploy/data/issuer/issuer.env            # their secrets, e.g. GOOGLE_ISSUER_CLIENT_SECRET=...
```

For each sign-in provider, register `https://issuer.<host>/callback/<id>` as
a redirect URI in its developer console. `<id>` is the provider's `id` in the
config.

Set the web addresses the issuer may send people back to. These are the
wallet's Vercel URL and the SENA extension's two addresses (its id is fixed):

```sh
WALLET_ORIGINS=https://sena-wallet.vercel.app,https://phkknehihpoajnkoiabbbknbjaonflad.chromiumapp.org,chrome-extension://phkknehihpoajnkoiabbbknbjaonflad deploy/setup.sh
```

## Operating it

| Task | Command (from `SENA/deploy`) |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f node relayer watcher` |
| Restart | `docker compose restart` |
| Update the code | `git -C .. pull && git -C ../../wallet pull && docker compose build && docker compose up -d` |
| Stop | `docker compose down` |

The chain, its keys and the Aptos accounts are in `deploy/data/`.
**Back it up.** It is the network:

```sh
sudo tar czf sena-backup-$(date +%F).tgz -C deploy data
```

Losing `data/aptos` loses the proposer's bonds, and losing `data/chain` loses
every balance.

### After a protocol change

An update that changes the transaction format or the contracts needs a new
chain and a new contract address. Move the old data aside and run the setup
again; the proposer needs funding again for the new publish.

```sh
docker compose down && sudo mv data data.old && ./setup.sh
```

## What it costs on Aptos

- **Publishing:** about 2.3 APT, once.
- **Each block:** about 0.001 APT of gas, plus a 0.01 APT bond. The bond comes
  back when the block's 24-hour challenge window closes. Blocks are only
  sealed when there are transactions, so an idle testnet costs nothing.

## Security notes

- Keys are plain files under `data/`, readable only by root. That's a
  test-network standard.
- The council is one key (`data/keys/council.json`), used only by `jwk-sync`.
- The node trusts `X-Forwarded-For` for rate limiting, because only Caddy can
  reach it. Do not publish its port.
- The watcher runs on the same server as the sequencer, so it is not
  independent. Anyone can run their own; see the
  [END_TO_END guide](../docs/END_TO_END.md#watch).
