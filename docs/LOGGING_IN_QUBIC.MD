# Event Logging in Qubic

## Overview

In the Qubic system, an event log represents the most primitive, discrete action that occurs within the network. All system activities, from simple transfers to complex smart contract executions, can be broken down and represented as a sequence of these fundamental events.

This logging mechanism provides a granular and auditable trail for all operations.

---

## Core System Events

The Qubic core protocol defines several fundamental event types. These include, but are not limited to:

* **QU Transfer (`QU_TRANSFER`):** Records the transfer of QUs from one identity to another.
* **Asset Transfer:** Records changes in the ownership, possession, or management rights of a given asset.
* **Burning:** Records the intentional destruction of QUs.
* **Dust Burning:** A rare event that burns many records that have low number of QUs to reduce the density of spectrum.

---

## Smart Contract Events

The Qubic smart contract system extends this capability, allowing developers to define and emit their own custom events.

* **Custom Events:** Any event defined by a smart contract developer to signal a specific, application-level occurrence.

---

## Deconstructing Complex Transactions

Every transaction or complex smart contract procedure can be deconstructed into a series of primitive Qubic events. This atomicity is crucial for transparency and data processing.

### Example: Asset Purchase

Consider a transaction where Alice sends 1000 QUs to an exchange (QX) to buy 11 units of Asset B. The exchange then sends Alice 11 units of Asset B and 50 QUs in change, while forwarding the remaining 950 QUs to Bob (the seller).

This single, complex transaction can be broken down into the following sequence of primitive events:

1.  **`QU_TRANSFER`** from Alice to QX (Amount: 1000)
2.  **`ASSET_TRANSFER`** from QX to Alice (AssetName: B, Amount: 11)
3.  **`QU_TRANSFER`** from QX to Alice (Amount: 50)
4.  **`QU_TRANSFER`** from QX to Bob (Amount: 950)

---

## Custom Event Logging for Backend Processing

In the smart contract system, developers can strategically emit custom events to facilitate efficient backend data processing. These events can be indexed by bob, allowing external services to query data efficiently.

By logging key events at critical points in the contract's logic, developers can avoid the need for complex and resource-intensive simulations to determine the outcome of a transaction. A backend service can instead track state changes by querying the indexed event logs directly.

### Example: Logging a Matched Trade

In a decentralized exchange smart contract, a developer might log a custom event every time a trade is matched:

```cpp
...
if (matchingOrder)
{
    // Populate the custom log structure
    matchingLog.src = qpi.invocator();
    matchingLog.dst = order.id;
    matchingLog.amount = order.amount;
    matchingLog.asset = order.asset;

    // Emit the custom event to be logged and indexed
    LOG_INFO(locals.matchingLog);
    ...
}
...