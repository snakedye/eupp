# **White Paper: Agnostic UTXO Payload Protocol (AUPP)**

## 1. Abstract

The **Agnostic UTXO Payload Protocol (AUPP)** is a minimalist blockchain designed for two primary purposes: **secure data storage** and **programmable transaction logic**.

AUPP introduces a **versioned UTXO system** that allows outputs to operate in two distinct modes:

* **Version 1 (Agnostic Mode):** Simple, signature-verified data anchoring
* **Version 2 (Programmable Mode):** Smart-contract execution via an internal virtual machine

Each output contains three core elements — an **Amount**, a **Data Payload**, and a **Cryptographic Commitment** — forming the minimal unit of blockchain state.

## 2. Transaction Architecture

AUPP uses the **UTXO (Unspent Transaction Output)** model, where the blockchain state is defined as the set of all unspent outputs.

### 2.1 Inputs

To spend an output, a transaction must specify:

* **Transaction ID:** The hash of the previous transaction
* **Output Index:** The index of the output being spent
* **Public Key:** The spender’s Ed25519 public key
* **Signature:** An Ed25519 signature proving authorization of the spend

### 2.2 Outputs

Each transaction output defines:

* **Version:** Protocol version (1 = Agnostic Mode, 2 = Programmable Mode)
* **Amount:** 64-bit unsigned integer representing the value transferred
* **Data:** 32 bytes payload (opaque in V1, executable code in V2)
* **Commitment:** 32-byte hash binding the public key to the data payload

The commitment is computed as:

```
H(public_key || data)
```

where `H` is a cryptographic hash function and `||` denotes concatenation.
This ensures both ownership and data integrity within each UTXO.

## 3. Verification Process

Each transaction must pass a universal and version-specific validation process before inclusion in a block.

### 3.1 Universal Validation Rules

These rules apply to all versions:

1. **Commitment Verification:**
   The commitment must equal `H(public_key || data)`.
2. **Value Conservation:**
   The sum of all outputs must be less than or equal to the sum of all inputs.
3. **Mining Reward Limit:**
   If spending the Lead UTXO (the mining reward), the reward must satisfy:

   ```
   R(D) ≤ min(100,000, 2^(floor(D/4)))
   ```

### 3.2 Version-Specific Validation

#### **Version 1 — Agnostic Mode**

* The `data` field is treated as opaque and stored without interpretation.
* Validation only requires a valid Ed25519 signature.
* Ideal for **data anchoring**, **timestamping**, or **cross-protocol references**.

#### **Version 2 — Programmable Mode**

* The `data` field contains **bytecode** for the internal virtual machine (VM).
* The VM executes in a **stack-based architecture**.
* Validation succeeds only if script execution terminates successfully.
* Bytecode can perform logic such as signature verification, arithmetic, and conditional branching — enabling programmable transaction logic and lightweight smart contracts.

## 4. Mining: Chained Mask Proof-of-Work (CM-PoW)

AUPP employs a novel consensus mechanism called **Chained Mask Proof-of-Work**, where each block’s mining challenge is derived directly from the previous block’s Lead UTXO commitment.

### 4.1 Mining Model

* The **Lead UTXO** (index 0 output) of the previous block defines the next mining challenge.
* Miners “spend” the Lead UTXO to produce the next block.
* Unlike conventional block rewards, AUPP’s total supply is **fixed at genesis**: miners redistribute the existing supply rather than mint new coins.

### 4.2 Mining Challenge

To mine a block, a miner must find an Ed25519 key pair whose **public key** satisfies:

```
(mask & public_key) == 0
```

Where:

* `mask` = commitment of the Lead UTXO from the previous block
* `&` = bitwise AND operator
* The public key must have zeros in all bit positions where the mask has ones

This rule creates a direct **cryptographic dependency** between consecutive blocks — the “Chained Mask.”


### 4.3 Mining Rewards

When a valid key pair is found, the miner spends the Lead UTXO and may claim a portion of the remaining supply according to the reward function:

```
R(D) = min(1_000_000, 2^(floor(D/4)))
```

Where:

* `D` = difficulty (number of 1-bits in the mask)
* Rewards grow exponentially with difficulty but are capped at 1,000,000 units

The miner creates a new Lead UTXO containing the remaining supply minus the claimed reward. This output becomes the Lead UTXO for the next block.

### 4.4 Chain Selection Rule — Maximum Accumulated Supply (MAS)

Instead of choosing the longest chain, AUPP nodes adopt the chain with the **highest total accumulated mining rewards**.

Formally, the **canonical chain** is the branch with the largest sum of all `R(D)` values from genesis to the current tip:

```
MAS(chain) = Σ R(D_i)
```

Nodes always prefer the chain with the highest `MAS`.

This incentivizes miners to pursue higher-difficulty challenges, aligning computational effort with consensus weight.

## 5. Discussion

AUPP’s architecture emphasizes **modularity**, **cryptographic minimalism**, and **forward extensibility**.

* The **versioned UTXO system** provides a clean separation between simple anchoring (V1) and programmable logic (V2).
* The **commitment function** `H(public_key || data)` ensures immutable binding of ownership and payload.
* The **Chained Mask PoW** introduces a new dimension of dependency between blocks — effectively “linking” miner identity and computation across time.
* The **MAS consensus rule** replaces chain length with accumulated work, creating a natural economic pressure toward higher difficulty and stability.

## 6. Conclusion

The **Agnostic UTXO Payload Protocol** defines a minimalist yet expressive blockchain foundation.
Through its dual-version outputs, AUPP supports both **data anchoring** and **programmable execution** without compromising simplicity or determinism.

By coupling mining difficulty with consensus weight via **Chained Mask Proof-of-Work**, and ensuring total supply conservation from genesis, AUPP achieves a transparent, self-limiting, and evolvable blockchain architecture.
