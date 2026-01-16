# **Experimental UTXO Payment Protocol (EUPP)**

## 1. Abstract

**EUPP** is a decentralized ledger protocol that tightly couples its transaction graph with its consensus mechanism. By utilizing a **Chained Mask** Proof of Work (PoW) and a stack-based Virtual Machine (VM) with forward-looking introspection, EUPP enables complex cryptographic covenants and a strictly linear, verifiable block progression.

## 2. The UTXO Model & Transaction Rules

The protocol operates on a Modified UTXO architecture where the state is a collection of spendable outputs.

### 2.1 Transaction Structure

- **Capacity:** The protocol enforces a limit of 256 inputs and 256 outputs per transaction to ensure efficient processing and prevent excessive computational overhead.  
- **Balance:** Transactions must satisfy the conservation rule, expressed as `sum(inputs) >= sum(outputs)` where **n** is the number of inputs and **m** is the number of outputs. 
This ensures that no new value is created within the transaction, maintaining the integrity of the ledger.
- **Pruning:** To optimize the state and reduce unnecessary data retention, outputs with a value of 0 are considered redundant and can be safely removed from the active UTXO set. This mechanism helps mitigate state bloat and ensures the scalability of the protocol over time.

### 2.2 Output Structure

Every UTXO consists of four distinct fields:

- **Version (1 byte):** Specifies the spending logic.  
- **Amount (4 bytes):** Represents the stored value in the output.  
- **Data (32 bytes):** Contains contextual state or VM bytecode, which can be used for programmable spending conditions.  
- **Commitment (32 bytes):** A cryptographic commitment that can serve as a locking mechanism.

### 2.3 Input Structure

Each transaction input references a specific UTXO and provides the necessary cryptographic proof to unlock it. The structure is defined as follows:

- **Output ID:** A reference to the UTXO being spent, consisting of:
  - **Transaction Hash (32 bytes):** The hash of the transaction containing the UTXO.
  - **Index (1 byte):** The position of the UTXO in the transaction's output list.
- **Public Key (32 bytes):** The Ed25519 public key corresponding to the private key used for signing.
- **Signature (64 bytes):** A cryptographic signature proving ownership of the referenced UTXO.
- **Witness (Variable):** Optional data used for advanced spending conditions or VM execution.

The input structure ensures that only the rightful owner of a UTXO can spend it, while also supporting extensibility for programmable spending logic.

### 2.4 The Lead UTXO Model

The entire unmined supply of the network is held in a single, rotating "Lead UTXO."

- **Sequentiality**: Every block must spend the Lead UTXO created by the previous block.
- **Auditability**: Total circulating supply is always exactly `Initial Supply - Current Lead UTXO Balance`. 
- **Fee Recycling**: Transaction fees are added back into the Lead UTXO balance, ensuring that the "mining reservoir" is replenished by the economy, allowing for a sustainable, infinite lifecycle.

## 3. Programmability: The EUPP VM

EUPP supports three logic versions. While **v1** is a standard P2PK script where the spender reveals a **pk** to match a hash commitment, **v2** introduces a programmable bytecode environment, and **v3** extends this functionality with Segregated Witness (SegWit) support.

The VM is a stack-based machine designed to process byte arrays and execute scripts that define spending conditions. It operates on a Modified UTXO model, enabling advanced programmability through its ability to evaluate custom logic embedded in transaction outputs. The VM supports a wide range of operations, including cryptographic verification, arithmetic, and data manipulation, allowing developers to implement complex spending rules.

Key capabilities of the EUPP VM include:

- **Stack-Based Execution:** The VM uses a stack to manage data and intermediate results, ensuring efficient and deterministic script execution.
- **Forward-Looking Introspection:** Scripts can access transaction-level metadata, such as input amounts, output commitments, and block height, enabling dynamic and context-aware logic.
- **Programmable Covenants:** Developers can create UTXOs with conditions that restrict how they can be spent, such as requiring specific outputs or enforcing time locks.
- **Segregated Witness (SegWit):** Introduced in **v3**, SegWit separates signature data from transaction data, improving scalability by allowing more transactions to fit within a block.
- **Extensibility:** The VM's design allows for the addition of new opcodes and features, ensuring adaptability to future use cases.

This programmable environment empowers developers to define custom transaction behaviors, enabling use cases such as multi-signature wallets, atomic swaps, and advanced financial instruments, all while maintaining the security and verifiability of the EUPP protocol.

## 4. Consensus: Chained Mask Proof of Work

Consensus in EUPP is defined by the transaction graph itself rather than an external block header hash.

### 4.1 The Mask Mechanism

1. **Lead UTXO:** The output at index 0 of the previous block defines the next challenge.  
2. **The Mask:** The **data** field of this Lead UTXO acts as a bitmask for the next miner. 
3. **Mining Condition:** A miner must find a solution such that the hash of the previous block, the miner's public key, and a nonce satisfies the mask condition:  
   `Mask & hash(prev_block_hash, pubkey, nonce) == 0`
4. **Commitment:** The miner includes the nonce as part of the commitment in the next **Lead UTXO**.

To successfully mine the block, the miner must create a transaction that **spends** this **Lead UTXO**.

### 4.2 Deterministic Mining

Miners can use a deterministic approach by deriving signing keys from a master seed and iterating through nonces to find a valid solution. This ensures reproducibility and fairness in the mining process.

### 4.3 Difficulty-Based Rewards

The block reward $R(d)$ is calculated as an asymptotic curve where the reward starts at $m$ and approaches $M$ as difficulty $d$ increases.

$$R(d) = M - \left\lfloor \frac{M - m}{2^{\lfloor d / H \rfloor}} \cdot (0.978)^{d \pmod H} \right\rfloor$$

#### Variables & Constants

- **d**: The difficulty, defined as the population count (number of set bits) in the 32-byte mask.
- **M**: `MAX_REWARD` (`1,000,000`).
- **m**: `MIN_REWARD` (`1`).
- **H**: `HALF_LIFE` (`32` bits).
- **0.978**: The bitwise decay factor (derived from the $978/1000$ scaling).

#### Logic
The function calculates the "gap" between the current difficulty and the maximum possible reward:
1.  **Macro Scaling**: Every $H$ (32) bits of difficulty halves the remaining gap ($2^{\lfloor d / H \rfloor}$).
2.  **Micro Scaling**: For every individual bit ($d \pmod H$), the gap is reduced by approximately $2.2\%$ ($0.978$ multiplier) to create a smooth transition between half-life steps.
3.  **Final Reward**: The resulting gap is subtracted from the `MAX_REWARD` and clamped to ensure it never falls below `MIN_REWARD`.

### 4.4 Market-Negotiated Equilibrium

Because the miner of Block $N$ sets the difficulty for Block $N+1$, the network operates on a value-driven equilibrium:
- **High Activity**: Users pay higher fees to be included in the sequential Lead UTXO transition.
- **Miner Response**: Miners set higher difficulties to claim higher asymptotic rewards and secure the high-value chain.
- **System Stability**: Block times naturally fluctuate based on the difficulty chosen by the market, rather than a hardcoded protocol constant.

### 4.5 Technical Architecture

#### Supply Preservation

Block validation enforces strict supply preservation. A block is only valid if the new Lead UTXO balance ($S_{next}$) satisfies:
$$S_{next} = S_{prev} + \sum \text{Fees} - \text{Reward}$$
This allows nodes to verify the entire block's economic integrity by auditing a single UTXO transition.

#### Virtual Size (vsize)

To prevent ledger bloat and spam, blocks are limited to a virtual size of 1,000,000 bytes. Without a fee market, miners have no incentive to include transactions; implementing fees aligns miner incentives with network utility.
