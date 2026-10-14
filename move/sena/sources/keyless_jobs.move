/// Keyless verification spread over several transactions.
///
/// Checking one keyless authorisation on Aptos costs more than a single
/// transaction may execute: the Poseidon public-input hash is ~10,000 field
/// operations, and each `crypto_algebra` call carries generic-dispatch and
/// feature-check overhead well beyond its native price. So when a dispute
/// needs a keyless transaction's verdict, anyone computes it here first:
///
/// 1. `start` decodes the transaction, runs the cheap checks (address
///    binding, horizon, expiry at the batch time, ephemeral signature), and
///    seeds the Poseidon state with the 14 public-input scalars;
/// 2. `advance` runs as many steps of the 69-step permutation as the caller
///    chooses, persisting the state;
/// 3. `finish` checks the Groth16 proof against the resulting hash and records
///    the verdict.
///
/// The verdict is keyed by `H(tx_bytes, batch time, setup)`, so it can only be
/// used for the transaction, time and parameters it was computed under, and
/// it is the same verdict `keyless::verify` gives in one call: every step is
/// deterministic and nothing is taken from the caller but bytes it cannot
/// influence the outcome of. `sena::disputes` reads it when a leaf is keyless.
module sena::keyless_jobs {
    use std::option;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use sena::codec;
    use sena::keyless;
    use sena::poseidon;
    use sena::txcodec;

    /// A job for this transaction, time and setup already exists.
    const E_ALREADY_STARTED: u64 = 1;
    /// No such job.
    const E_NO_SUCH_JOB: u64 = 2;
    /// The job has already produced its verdict.
    const E_FINISHED: u64 = 3;
    /// The permutation has not run to completion yet.
    const E_NOT_READY: u64 = 4;
    /// The bytes are not a keyless transaction; compile them directly.
    const E_NOT_KEYLESS: u64 = 5;

    const DOMAIN_KEYLESS_JOB: vector<u8> = b"SENA:v1:keyless-job";

    struct Job has store, drop {
        setup: u8,
        proof: vector<u8>,
        state: vector<vector<u8>>,
        next_step: u64,
        finished: bool,
        verdict: bool,
    }

    struct Jobs has key {
        jobs: Table<vector<u8>, Job>,
    }

    /// Creates the job store. Called by `disputes::initialize`.
    public fun create(admin: &signer) {
        move_to(admin, Jobs { jobs: table::new() });
    }

    /// The key a verdict is stored under.
    public fun job_id(tx_bytes: vector<u8>, timestamp: u64, setup: u8): vector<u8> {
        let buf = codec::begin(DOMAIN_KEYLESS_JOB);
        codec::put_field(&mut buf, tx_bytes);
        codec::put_field_u64(&mut buf, timestamp);
        codec::put_field_u64(&mut buf, (setup as u64));
        codec::commit(buf)
    }

    /// Starts verifying a keyless transaction as of `timestamp` under `setup`.
    /// Permissionless.
    public entry fun start(
        _caller: &signer,
        store_addr: address,
        tx_bytes: vector<u8>,
        timestamp: u64,
        setup: u8,
    ) acquires Jobs {
        let id = job_id(tx_bytes, timestamp, setup);
        let jobs = &mut borrow_global_mut<Jobs>(store_addr).jobs;
        assert!(!table::contains(jobs, id), E_ALREADY_STARTED);

        let decoded = txcodec::decode(tx_bytes);
        assert!(option::is_some(&decoded), E_NOT_KEYLESS);
        let tx = option::extract(&mut decoded);
        let sig_opt = txcodec::keyless_signature(&tx);
        assert!(option::is_some(&sig_opt), E_NOT_KEYLESS);
        let sig = option::extract(&mut sig_opt);

        let finished_false = Job {
            setup, proof: vector::empty(), state: vector::empty(), next_step: 0,
            finished: true, verdict: false,
        };
        let digest = txcodec::signing_digest(&tx);
        if (!keyless::precheck(setup, &sig, &txcodec::sender(&tx), &digest, timestamp)) {
            table::add(jobs, id, finished_false);
            return
        };
        let scalars = keyless::public_input_scalars(&sig);
        if (option::is_none(&scalars)) {
            table::add(jobs, id, finished_false);
            return
        };
        let state = poseidon::initial_state(option::borrow(&scalars));
        table::add(jobs, id, Job {
            setup,
            proof: keyless::proof(&sig),
            state: poseidon::encode_state(&state),
            next_step: 0,
            finished: false,
            verdict: false,
        });
    }

    /// Runs up to `max_steps` more steps of the permutation. Permissionless.
    public entry fun advance(
        _caller: &signer,
        store_addr: address,
        id: vector<u8>,
        max_steps: u64,
    ) acquires Jobs {
        let jobs = &mut borrow_global_mut<Jobs>(store_addr).jobs;
        assert!(table::contains(jobs, id), E_NO_SUCH_JOB);
        let job = table::borrow_mut(jobs, id);
        assert!(!job.finished, E_FINISHED);
        let total = poseidon::steps();
        let to = if (job.next_step + max_steps > total) { total } else { job.next_step + max_steps };
        let state = poseidon::decode_state(&job.state);
        poseidon::run(&mut state, job.next_step, to);
        job.state = poseidon::encode_state(&state);
        job.next_step = to;
    }

    /// Checks the proof against the finished hash and records the verdict.
    /// Permissionless.
    public entry fun finish(
        _caller: &signer,
        store_addr: address,
        id: vector<u8>,
    ) acquires Jobs {
        let jobs = &mut borrow_global_mut<Jobs>(store_addr).jobs;
        assert!(table::contains(jobs, id), E_NO_SUCH_JOB);
        let job = table::borrow_mut(jobs, id);
        assert!(!job.finished, E_FINISHED);
        assert!(job.next_step == poseidon::steps(), E_NOT_READY);
        let state = poseidon::decode_state(&job.state);
        job.verdict = keyless::groth16_verify(job.setup, &job.proof, vector::borrow(&state, 0));
        job.finished = true;
        job.state = vector::empty();
    }

    /// `(true, verdict)` once a job has finished, `(false, false)` otherwise.
    public fun verdict(store_addr: address, id: vector<u8>): (bool, bool) acquires Jobs {
        let jobs = &borrow_global<Jobs>(store_addr).jobs;
        if (!table::contains(jobs, id)) { return (false, false) };
        let job = table::borrow(jobs, id);
        (job.finished, job.verdict)
    }

    #[view]
    /// How far a job has got, for clients driving it: `(next_step, finished)`.
    public fun progress(store_addr: address, id: vector<u8>): (u64, bool) acquires Jobs {
        let jobs = &borrow_global<Jobs>(store_addr).jobs;
        assert!(table::contains(jobs, id), E_NO_SUCH_JOB);
        let job = table::borrow(jobs, id);
        (job.next_step, job.finished)
    }
}
