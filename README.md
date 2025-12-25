# White Paper: Agnostic UTXO Payload Protocol (AUPP)

## Brainstorm

- UTXO model
  - Input: [version, tx_id, output_index, sig, pk]
    - **sig**=sign(sk,Hash(tx_id∥output_index∥all_new_outputs))
  - Output: [data (u64), H(pk)]
    - It's up to higher protocols to determine how to use the data.
- To spend a transaction you need to :
  - Reveal the pk
- Payment flow :
  1. Receiver creates a sk/pk pair
  2. Receiver hashes his pk -> H(pk)
  3. Sender owns UTXO for H(sender_pk)
  4. Sender create a transaction :
  	- Input: [version, tx_id, output_index, sig, sender_pk]
  	- Output: [data, H(pk)]
- To know if a transaction is valid, a node just checks if :
  - The pk hashes to H(pk)
  - **sig** was made with he sk of the sender
- Mining works by spending the first UTXO in the previous block
- The PoW will be embedded in the hash of the UTXO ie :
  - H(x) in the minting UTXO will only be a mask (ex: 11111100 could be a 32 bit mask)
  - To spend you need to give an x where all the 0s in the mask are 0 in x.

## 1. Abstract

The Agnostic UTXO Payload Protocol (AUPP) is a minimalist, secure distributed ledger design. Unlike traditional blockchains that hardcode currency "amounts," AUPP treats transaction outputs as arbitrary 64-bit unsigned integer (u64) payloads. This design creates a "Layer 1" that is strictly a verification and ordering layer, leaving the semantic interpretation of the data—whether it represents currency, voting weight, or game assets—to Layer 2 protocols.

## 2. Transaction Architecture

A transaction consists of two primary components: **Inputs** and **Outputs**.

### 2.1 Input Structure

Each input represents a claim on an existing unspent output. It contains:

- **Version**: Protocol versioning for forward compatibility.
- **Transaction ID (tx_id)**: A hash of the previous transaction containing the funds.
- **Output Index (output_id)**: The specific index of the output being spent.
- **Public Key (pk)**: The key used to verify the spender's authority.
- **Signature (sig)**: The cryptographic proof of authorization.

### 2.2 Output Structure

Each output defines the new state of the assets:

- **Agnostic Payload** (u64): An arbitrary 64-bit value.
- **Recipient**: The destination address (script or public key hash).

## 3. Cryptographic Security Model

The security of the LUTA protocol relies on a "Sighash" (Signature Hash) preimage that binds the signature to the transaction context.

### 3.1 Signature Generation

To authorize a spend, the sender signs a hash containing both the **source** (to prevent replay on other inputs) and the **destination** (to prevent tampering).

The signature is generated as follows:
	```
	sig=sign(sk,Hash(tx_id∥output_index∥all_new_outputs))
	```
### 3.2 Security Properties

- **Replay Protection**: Because the  and  are included in the signed message, a signature used for "Input A" cannot be reused for "Input B," even if both are owned by the same user.
- **Integrity**: Any modification to the amounts or recipients in  will invalidate the hash, causing the signature verification to fail.
- **Non-Repudiation**: The use of the secret key () ensures that only the rightful owner could have generated the signature.

## 4. Verification Workflow

Nodes in the network validate transactions by executing the following logic:

1. **Reconstruction**: The node gathers the tx_id, output_id and the list of proposed outputs from the transaction.
2. **Hashing**: The node creates a local hash of these components.
3. **Validation**: Using the provided Public Key (pk), the node verifies the signature against the local hash.
4. **Finality**: If Vpk​(sig,Hash)=True, the transaction is considered authorized and added to the ledger.

## 5. Mining Protocol: Chained Mask Proof-of-Work (CM-PoW)

Unlike traditional PoW where miners hash a static header, CM-PoW integrates consensus into the UTXO set. Mining is defined as the act of successfully spending the **"Lead UTXO"** from the previous block.

### 5.1 The Minting UTXO

Every block contains a special output at index 0, known as the **Minting UTXO**. This output contains a cryptographic challenge instead of a standard public key requirement.

- **The Mask ():** A  value (e.g., `0xFFFFFFF0`) that defines the difficulty.
- **The Challenge:** To spend this UTXO, a miner must provide a preimage  such that the bits defined by the mask satisfy a specific condition.

### 5.2 Mining as a Transaction

To "mine" a block, a miner creates a transaction that consumes the previous block's Minting UTXO.

- **Input:**  (The solution to the mask).
- **Validation:** The network checks that .
- **Evolution:** The successful miner creates a *new* Minting UTXO for the next block, potentially with an updated Mask to adjust difficulty.

### 5.3 Protocol Benefits

- **Sequence Integrity:** It is impossible to mine Block  without knowing the output of Block , as the input for the next mining event is physically tied to the previous output.
- **State Pruning:** Consensus data lives within the UTXO set, allowing nodes to verify the "tip" of the chain by looking at the spendability of the current Minting UTXO.
- **Simplified L1:** The logic for "mining" is just another type of script validation in the L1 engine.

## 6. Conclusion

AUPP provides a "dumb" base layer that offers "smart" security. By moving logic to the edges (Layer 2) and maintaining a rigid, context-aware signature model at the core, the protocol achieves maximum flexibility without sacrificing cryptographic integrity.
