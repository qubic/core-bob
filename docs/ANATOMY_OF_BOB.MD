# The anatomy of BOB

## Core Processors

The core of BOB consists of four main processors dedicated to syncing and verifying network data.

* **Thread #1: Tick Data Requester**
    * This thread constantly queries the network for new tick data, votes, and transactions.
    * It performs a pre-check to ensure data sufficiency (e.g., 451+ votes agree to execute the same tick, or 226+ votes agree on an empty tick).

* **Thread #2: Logging Event Requester**
    * This thread queries the network for logging and event data on a per-tick basis, adhering to the Qubic logging event protocol.
    * It first requests the `logId` range for each transaction within a tick and then fetches all associated logging data for that tick.

* **Thread #3: Data Integrity Verifier**
    * This thread verifies the integrity of all data collected by the threads above.
    * As logging events represent the most primitive actions in Qubic, they are used to reconstruct and validate the Spectrum and Universe every tick.

* **Thread #4: Indexer**
    * After the data has been successfully verified, this thread indexes it to ensure it is easily searchable.

---

## Additional Modules

Beside the core processors, BOB also features two optional modules that can be disabled without halting its functionality.

* **TCP Server**
    * This server mimics the behavior of a core baremetal for critical request/response cycles (e.g., requests for `tickData`, `votes`, `transactions`).
    * Its purpose is to help strengthen the existing network.

* **REST API Server**
    * This server provides a developer-friendly interface for builders to access all the indexed data mentioned above.