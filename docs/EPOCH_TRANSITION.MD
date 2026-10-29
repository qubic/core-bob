## Protocol for Epoch Finalization and State Transition

### 1. End-of-Epoch Event Handling

Upon the conclusion of each epoch, the protocol dispatches a series of `END_EPOCH` events.

To ensure compatibility with the existing logging event protocol, all events generated during this phase are aggregated into a new, temporary tick. This tick is assigned the sequential identifier **(N+1)**, where `N` represents the identifier of the final tick from the concluded epoch.

### 2. The Virtual Tick Mechanism

The `(N+1)` tick is designated as a **virtual tick** and is distinct from standard ticks. Its properties are as follows:

* **No Consensus Data:** The virtual tick does not contain `TickData` or `TickVote` payloads.
* **No Quorum:** As it lacks voting data, this tick does not undergo a consensus or quorum validation process.
* **Deferred State Verification:** The final verification of the chain state resulting from these events is deferred until the commencement of the next epoch.

### 3. States Generation

Bob create the new epoch's spectrum and universe states once it has finished processing the entire set of END_EPOCH event logging data.

### 4. Operational Requirements for the "Bob" Component

After it has finalized the processing of the `END_EPOCH` event, Bob keeps serving for `wait_at_epoch_end` seconds (default `1800`, i.e. 30 minutes) and then performs a graceful exit.

To ensure continuous operation and readiness for the next epoch, Bob must be restarted after this exit. By default the `bob` binary runs a built-in watchdog parent process that relaunches the Bob child automatically, so no extra setup is needed. Only if you run Bob with `-no-watchdog` (e.g. `bob bob.json -no-watchdog`) must you deploy it within a persistent execution framework (e.g., a `systemd` service, a container orchestrator, or a custom wrapper script) that guarantees its automatic restart. This enables the component to initialize and begin processing the new epoch.