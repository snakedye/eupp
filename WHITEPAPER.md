# **Experimental UTXO Payment Protocol (EUPP)**

## 1. Abstract

**EUPP** is a decentralized ledger protocol that tightly couples its transaction graph with its consensus mechanism. By utilizing a **Chained Mask** Proof of Work (PoW) and a stack-based Virtual Machine (VM) with forward-looking introspection, EUPP enables complex cryptographic covenants and a strictly linear, verifiable block progression.

## 2. The UTXO Model & Transaction Rules

The protocol operates on a UTXO architecture where the state is a collection of spendable outputs.

### 2.1 Transaction Structure

Very much like Bitcoin, EUPP transactions consist of inputs and outputs. Each input spends a UTXO, while each output creates a new UTXO.

In order to spend a UTXO to the next transaction, each input must provide a valid signature that proves ownership of the UTXO while additionally satisfying the spending conditions of the output spent.

> utxo_spending_diagram

### 2.2 The Lead UTXO Model

A novel idea introduced in the EUPP protocol is the **Lead UTXO (LUTXO)** model.

The **LUTXO** is a special UTXO that holds the entire unmined supply of the network.

It is created by the first block to define the initial supply of the network and spent when miners claim the reward.
When the **LUTXO** of the current block is spent, the following **LUTXO** is created by the miner with the following amount:

$$S_{prev} - \text{Reward} \le S_{next} \le S_{prev} + \sum \text{Fees}$$ 

This allows nodes to verify the block's economic integrity by auditing a single UTXO transition.

#### Fees

Fees are defined as amount in inputs not spent in outputs. For example, if an input has a value of 100 and the output has a value of 90, the fee is 10.

Transaction fees from all non-mining transactions in a block are collected by the miner. The protocol allows these fees to be rolled into the new **LUTXO**, as its new amount is permitted to be as high as the previous amount plus the sum of all collected fees. This mechanism recycles value back into the primary supply pool, creating a sustainable economic loop where network usage directly replenishes the funds available for future mining rewards.

## 3. Programmability: The EUPP VM

EUPP supports multiple logic versions. While **v1** is a standard P2PKH script where the spender reveals a public key to match a hash commitment, **v2** introduces a programmable bytecode environment, and **v3** extends this functionality with Segregated Witness (SegWit) support.

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

1. **Lead UTXO:** The **LUTXO** from the previous block defines the mining challenge for the current block.
2. **The Mask:** The **data** field of this previous **LUTXO** acts as a bitmask for the current miner.
3. **Mining Condition:** A miner must find a solution such that the hash of the previous block, the miner's public key, and a nonce satisfies the mask condition:
   `Mask & hash(prev_block_hash, pubkey, nonce) == 0`
4. **Commitment:** The miner includes the successful nonce as part of the commitment in the new **Lead UTXO** they create in the current block.

To successfully mine the block, the miner must create a transaction that **spends** the previous block's **LUTXO** by including the successful nonce in the **commitment** field of the **LUTXO**.

### 4.2 Difficulty-Based Rewards

The block reward $R(d)$ is calculated as an asymptotic curve where the reward starts at $m$ and approaches $M$ as difficulty $d$ increases.

$$R(d) = M - \left\lfloor \frac{M - m}{2^{\lfloor d / H \rfloor}} \cdot (0.978)^{d \pmod H} \right\rfloor$$ 

#### Variables & Constants

- **d**: The difficulty, defined as the population count (number of set bits) in the 32-byte mask.
- **M**: `MAX_REWARD` (`1,000,000`).
- **m**: `MIN_REWARD` (`1`).
- **H**: `HALF_LIFE` (`32` bits).
- **0.978**: The bitwise decay factor (derived from the `978/1000` scaling).

#### Logic

The function calculates the "gap" between the current difficulty and the maximum possible reward:
1.  **Macro Scaling**: Every $H$ (32) bits of difficulty halves the remaining gap ($2^{\lfloor d / H \rfloor}$).
2.  **Micro Scaling**: For every individual bit ($d \pmod H$), the gap is reduced by approximately $2.2\%$ ($0.978$ multiplier) to create a smooth transition between half-life steps.
3.  **Final Reward**: The resulting gap is subtracted from the `MAX_REWARD` and clamped to ensure it never falls below `MIN_REWARD`.

> difficulty_curve_graph

### 4.3 Chain Selection: Heaviest Chain Rule

The canonical chain is determined by the "heaviest chain" rule, which selects the valid chain with the most accumulated Proof of Work.

- **Block Work**: The work for a single block is calculated as `2^d`, where `d` is the difficulty (the number of set bits in the mask).
- **Cumulative Work**: Each block stores a `cumulative_work` value, which is the sum of its own work and the `cumulative_work` of its parent block.
- **Chain Selection**: When multiple chains (forks) exist, the one with the highest `cumulative_work` at its tip is considered the valid, canonical chain. This ensures that the chain representing the most computational effort is the one that the network follows.

### 4.4 Market-Negotiated Equilibrium

Because the miner of Block $N$ sets the difficulty (the mask in the new Lead UTXO) for Block $N+1$, the network operates on a value-driven equilibrium:
- **High Activity**: Users pay higher fees to be included in blocks.
- **Miner Response**: When fees are high, miners are incentivized to set a higher difficulty for the next block to claim a larger asymptotic reward, securing the now more valuable chain.
- **System Stability**: Block times naturally fluctuate based on the difficulty chosen by the market, rather than a hardcoded protocol constant.

### 4.5 Deterministic Mining

Miners can use a deterministic approach by deriving signing keys from a master seed and iterating through nonces to find a valid solution. This ensures reproducibility and fairness in the mining process.

### 4.6 Technical Architecture

#### Supply Preservation

Block validation enforces strict supply preservation by constraining the value of the new Lead UTXO. A block is only valid if the new Lead UTXO balance ($S_{next}$) is within a specific range determined by the previous balance ($S_{prev}$), the block reward, and transaction fees:

$$S_{prev} - \text{Reward} \le S_{next} \le S_{prev} + \sum \text{Fees}$$ 


#### Virtual Size (vsize)

To prevent ledger bloat and spam, blocks are limited to a virtual size of 1,000,000 bytes. The virtual size calculation discounts certain data, like witness data and zero-value outputs, to align incentives with efficient ledger growth.
