# Experimental UTXO Payment Protocol (EUPP)

## 1. Abstract

EUPP is a compact, experimental UTXO ledger and reference node designed to explore programmable outputs and an alternative PoW construction. Its primary innovations are: the Lead UTXO (LUTXO) — a single, mutable UTXO that represents the mint pool; a Chained Mask proof-of-work that lets miners encode future difficulty; and a stack-based virtual machine that enables expressive spending conditions. The goal is a simple, auditable economic model and an expressive, verifiable transaction environment.

## 2. UTXO model & transaction rules

EUPP follows the UTXO model: state is a set of unspent outputs, and transactions consume outputs (inputs) and produce new outputs.

### 2.1 Transaction structure

Transactions contain inputs and outputs. Inputs reference previous outputs and must satisfy the spending conditions defined by those outputs (typically by presenting signatures and any required witness data). Outputs carry an amount and a spending condition (script/data) that determines how they may be spent in the future.

### 2.2 Lead UTXO (LUTXO) model

The Lead UTXO (LUTXO) is a designated UTXO that functions as the mutable mint pool for the network. It is created at chain start to represent the initial unmined supply and is subsequently spent by miners when claiming block rewards.

Policy summary:

- Each mined block consumes the prior block's LUTXO as part of the mining transaction.
- A successful mining transaction creates a new LUTXO that carries the updated mint pool, the next mining challenge (mask), and the miner’s commitment/proof.
- The new LUTXO amount is bounded by the previous supply, the miner reward, and collected fees. In equation form:
  
$$ S_{prev} - Reward \leq S_{next} \leq S_{prev} + \sum Fees $$

Fees are the difference between input and output totals for non-mining transactions in a block; miners collect fees and may roll them back into the LUTXO to replenish the mint pool.

## 3. Programmability: the EUPP VM

EUPP supports multiple script/logic versions:

- v1: simple public-key based spending (P2PKH-style).
- v2: programmable bytecode for richer spending conditions.
- v3: extends programmability with segregated witness semantics.

The VM is intentionally compact and stack-based. It enables:

- deterministic script execution,
- access to transaction-level context when needed,
- programmable covenants and time/height checks,
- extensibility for new opcodes or logic versions.

These capabilities allow common primitives (multisig, timelocks, atomic swap patterns) while preserving clear validation semantics.

## 4. Consensus: Chained Mask Proof-of-Work

EUPP defines mining as a mask-based proof: miners must produce a candidate that satisfies constraints encoded by a mask. Consensus is expressed through spending and creating the LUTXO within the transaction graph rather than a separate header-only construction.

### 4.1 Mask concept and mining solution

At a high level:

- A mask encodes which bits in a miner's candidate are constrained: more set bits imply a stricter challenge.
- A miner's candidate (solution) is derived from the previous block context, the miner's identity (e.g., public key), and an arbitrary nonce; this candidate is tested against the mask.
- When a miner finds a valid candidate, they include the corresponding proof/commitment in the new LUTXO created by their mining transaction.

This design makes the mining challenge part of the spending semantics: to mine, a miner must legitimately spend the prior LUTXO and publish the proof as part of the new LUTXO.

#### 4.1.1 Proof-of-Work Verification

$$
\text{hash}(H(B_{n-1}), pk, nonce) \land M = M
$$

Where:

- $H(B_{n-1})$ is the hash of the previous block,
- $pk$ is the miner's public key,
- $nonce$ is an arbitrary value chosen by the miner,
- $M$ is the mask defining the mining challenge,

This equation ensures that the resulting hash, when masked, matches the mask $M$, thereby proving that the miner has met the required difficulty constraints.



### 4.2 Difficulty and rewards (intuitive)

Rewards follow an asymptotic curve: as the mask-imposed difficulty increases, the per-block reward approaches an upper cap; low or zero difficulty yields a minimal base reward (a spam-protection floor). The curve is shaped to provide diminishing marginal reward as difficulty grows — the intent is to balance miner incentives against block scarcity.

Conceptually:
- Difficulty is determined by how many constraints the mask imposes.
- Higher difficulty → larger reward (up to a cap).
- A zero-difficulty challenge returns a small minimum reward to discourage trivial blocks.

The reward curve is governed by the asymptotic formula:

$$
R(d) = M - \left\lfloor \frac{M - m}{2^{\lfloor d / H \rfloor}} \cdot (0.978)^{d \bmod H} \right\rfloor,
$$

where d is the difficulty (number of constrained mask bits), M is the maximum reward, m is the minimum reward, and H is the half-life parameter.

### 4.3 Chain selection

The canonical chain is chosen by accumulated work: each block contributes work proportional to the difficulty it enforces, and the chain with the most total work is preferred. This is the usual “heaviest-chain” principle adapted to mask-based difficulties.

### 4.4 Economic and security considerations

- Miner-set difficulty is an economic lever: miners may adjust the next mask based on fee conditions and expected rewards.
- A market for block inclusion (fees) interacts with miner choices: when fees are high, miners can safely increase difficulty to chase larger rewards.
- Clients must follow confirmations/finality best practices: heavier cumulative work gives stronger safety against reorgs, but recent blocks remain probabilistic until sufficient work accumulates.

Short risks to keep in mind:

- Miner strategies that repeatedly seek extreme masks can affect block times; fee dynamics and reward shaping constrain incentives.
- As with any PoW system, reorgs and selfish-mining vectors are possible; confirmation depth remains the recommended protection.
