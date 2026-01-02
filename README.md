# **Experimental UTXO Payment Protocol (EUPP)**

## 1. Abstract

**EUPP** is a decentralized ledger protocol that tightly couples its transaction graph with its consensus mechanism. By utilizing a **Chained Mask** Proof of Work (PoW) and a stack-based Virtual Machine (VM) with forward-looking introspection, EUPP enables complex cryptographic covenants and a strictly linear, verifiable block progression.

## 2. The UTXO Model & Transaction Rules

The protocol operates on a Modified UTXO architecture where the state is a collection of spendable outputs.

### 2.1 Transaction Structure

* **Capacity:** The protocol enforces a limit of 256 inputs and 256 outputs per transaction to ensure efficient processing and prevent excessive computational overhead.  
* **Balance:** Transactions must satisfy the conservation rule, expressed as `sum(inputs) >= sum(outputs)` where **n** is the number of inputs and **m** is the number of outputs. 
This ensures that no new value is created within the transaction, maintaining the integrity of the ledger.
* **Pruning:** To optimize the state and reduce unnecessary data retention, outputs with a value of 0 are considered redundant and can be safely removed from the active UTXO set. This mechanism helps mitigate state bloat and ensures the scalability of the protocol over time.

### 2.2 Output Structure

Every UTXO consists of four distinct fields:

* **Version (1 byte):** Specifies the spending logic, with supported versions being V0, V1, or V2.  
* **Amount (u64):** Represents the stored value in the output.  
* **Data (32 bytes):** Contains contextual state or VM bytecode, which can be used for programmable spending conditions.  
* **Commitment (32 bytes):** A cryptographic commitment that can serve as a locking mechanism or as part of the Proof of Work (PoW) mask.

### 2.3 Input Structure

Each transaction input references a specific UTXO and provides the necessary cryptographic proof to unlock it. The structure is defined as follows:

* **Output ID:** A reference to the UTXO being spent, consisting of:
  * **Transaction Hash (32 bytes):** The hash of the transaction containing the UTXO.
  * **Index (4 bytes):** The position of the UTXO in the transaction's output list.
* **Public Key (32 bytes):** The Ed25519 public key corresponding to the private key used for signing.
* **Signature (64 bytes):** A cryptographic signature proving ownership of the referenced UTXO.
* **Witness (Variable):** Optional data used for advanced spending conditions or VM execution.

The input structure ensures that only the rightful owner of a UTXO can spend it, while also supporting extensibility for programmable spending logic.

## 3. Programmability: The EUPP VM

EUPP supports three logic versions. While **v1** is a standard P2PK script where the spender reveals a **pk** to match a hash commitment, **v2** introduces a programmable bytecode environment, and **v3** extends this functionality with Segregated Witness (SegWit) support.

The VM is a stack-based machine designed to process byte arrays and execute scripts that define spending conditions. It operates on a Modified UTXO model, enabling advanced programmability through its ability to evaluate custom logic embedded in transaction outputs. The VM supports a wide range of operations, including cryptographic verification, arithmetic, and data manipulation, allowing developers to implement complex spending rules.

Key capabilities of the EUPP VM include:

- **Stack-Based Execution:** The VM uses a stack to manage data and intermediate results, ensuring efficient and deterministic script execution.
- **Forward-Looking Introspection:** Scripts can access transaction-level metadata, such as input amounts, output commitments, and block height, enabling dynamic and context-aware logic.
- **Programmable Covenants:** Developers can create UTXOs with conditions that restrict how they can be spent, such as requiring specific outputs or enforcing time locks.
- **Segregated Witness (SegWit):** Introduced in **v3**, SegWit separates signature data from transaction data, reducing transaction malleability and improving scalability by allowing more transactions to fit within a block.
- **Extensibility:** The VM's design allows for the addition of new opcodes and features, ensuring adaptability to future use cases.

This programmable environment empowers developers to define custom transaction behaviors, enabling use cases such as multi-signature wallets, atomic swaps, and advanced financial instruments, all while maintaining the security and verifiability of the EUPP protocol.

## 4. Consensus: Chained Mask Proof of Work

Consensus in EUPP is defined by the transaction graph itself rather than an external block header hash.

### 4.1 The Mask Mechanism

1. **Lead UTXO:** The output at index 0 of the previous block defines the next challenge.  
2. **The Mask:** The commitment of this Lead UTXO acts as a bitmask for the next miner.  
3. **Mining Condition:** A miner must find an Ed25519 public key (`pk`) such that: `Mask & hash(pk, prev_block_hash) == 0`

To successfully mine the block, the miner must create a transaction that **spends** this Lead UTXO.

### 4.2 Difficulty-Based Rewards

The difficulty (`D`) is determined by the number of 1-bits in the mask. The reward grows exponentially to incentivize solving harder masks:

```
R(D) = min(1000000, 2^(floor(D/4)))
```
