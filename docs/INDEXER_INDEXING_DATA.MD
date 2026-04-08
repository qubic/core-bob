# BOB Indexer: 2D Log Index

## 1. Overview: The Library Analogy

Imagine the indexer (Bob) is managing a massive library containing millions of drawers and cards. A developer's query, such as "At which tick did event `E` happen?" requires an efficient way to find the right information.

The 2D log index provides this structure.

---

## 2. The Two Dimensions

### Dimension 1: The "Drawer" (Event Signature)

The first dimension is a map, structured as a **Merkle tree**. The "key" for this map (the label on the drawer) is a unique combination of the following event parameters:

* SC Index
* Log Type
* Topic 1
* Topic 2
* Topic 3

### Dimension 2: The "Cards" (Tick Numbers)

Inside each "drawer" (i.e., for each unique event signature) is the second dimension: a simple, verifiable list (an **accumulator**) of all the tick numbers where that specific event occurred.

---

## 3. Indexing Example: QX Market Buy

Let's use a real-world example: Alice makes a market buy at **tick 2025**.

### Event Log Parameters

The log event has the following parameters:

* **SC index:** `1`
* **Log type:** `100001` (Note: Bob only indexes `logType >= 100000`)
* **topic1 (maker):** `Alice`
* **topic2 (taker):** `Charlie`
* **topic3 (asset):** `RANDOM`

### Indexing Actions

After scanning this log, Bob will add the tick number `2025` to nine different "drawers" (index keys) to allow for flexible querying. `ANY` acts as a wildcard for fields that are not specified in the key.
```
- add `2025` to drawer with label `SCIndex=1;ANY;ANY;ANY;ANY`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;ANY;ANY;ANY`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;topic1;ANY;ANY`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;ANY;topic2;ANY`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;ANY;ANY;topic3`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;topic1;topic2;ANY`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;ANY;topic2;topic3`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;topic1;ANY;topic3`
- add `2025` to drawer with label `SCIndex=1;LogType=100001;topic1;topic2;topic3`
```
---

## 4. Storage Considerations

While this appears to create many index entries, the actual storage cost is highly efficient:

* **Cost per event:** ~3 KiB
* **Estimated total per epoch:** ~15 GiB

This cost makes the 2D indexing model entirely feasible with current storage hardware.