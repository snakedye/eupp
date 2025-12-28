# **Another UTXO Payment Protocol (AUPP)**

## **1. Abstract**

**AUPP** is a decentralized ledger protocol that tightly couples its transaction graph with its consensus mechanism. By utilizing a **Chained Mask** Proof of Work (PoW) and a stack-based Virtual Machine (VM) with forward-looking introspection, AUPP enables complex cryptographic covenants and a strictly linear, verifiable block progression.

**2. The UTXO Model & Transaction Rules**

The protocol operates on a Modified UTXO architecture where the state is a collection of spendable outputs.

### **2.1 Transaction Structure**

* **Capacity:** Each transaction supports a maximum of 256 inputs and 256 outputs.  
* **Balance:** The sum of input amounts must be greater than or equal to the sum of output amounts.  
* **Pruning:** Transactions with an amount of 0 are considered prunable from the active UTXO set to prevent state bloat.

### **2.2 Output Structure**

Every UTXO consists of four distinct fields:

* **Version (1 byte):** Defines the spending logic (v1 or v2).  
* **Amount (Integer):** The stored value.  
* **Data (32 bytes):** Contextual state or VM bytecode.  
* **Commitment (32 bytes):** Used for cryptographic locking or as a PoW mask.

### **2.3 Input Structure**

To spend a UTXO, an input must provide a reference (tx\_id, output\_id) along with a public key ($pk$) and a signature ($sig$). The signature covers the spending intent:

$$sig = \text{sign}(sk, \text{Hash}(tx\_id \\\parallel output\_id \\\parallel all\_new\_outputs))$$

**3\. Programmability: The AUPP VM**

AUPP supports two logic versions. While **v1** is a standard P2PK script where the spender reveals a $pk$ to match a hash commitment, **v2** introduces a programmable bytecode environment.

The VM is a stack-based machine processing byte arrays. It features unique opcodes for **Introspection** and **State Awareness**:

* **Forward Visibility:** Opcodes like OP_OUT_AMT, OP_OUT_DATA, and OP_OUT_COMM allow a script to inspect the outputs of the transaction currently spending it.  
* **Input Context:** OP_PUSH_PK and OP_PUSH_SIG allow the script to access the specific credentials provided in the input.  
* **Global State:** OP_HEIGHT and OP_SUPPLY provide the script with the current block height and circulating supply.

**4. Consensus: Chained Mask Proof of Work**

Consensus in AUPP is defined by the transaction graph itself rather than an external block header hash.

### **4.1 The Mask Mechanism**

1. **Lead UTXO:** The output at index 0 of the previous block defines the next challenge.  
2. **The Mask:** The commitment of this Lead UTXO acts as a bitmask for the next miner.  
3. Mining Condition: A miner must find an Ed25519 public key ($pk$) such that:
$$(\text{mask} \land \text{pk}) = 0$$

To successfully mine the block, the miner must create a transaction that **spends** this Lead UTXO.

### **4.2 Difficulty-Based Rewards**

The difficulty ($D$) is determined by the number of 1-bits in the mask. The reward grows exponentially to incentivize solving harder masks:

$$R(D) = \min(1000000, 2^{\lfloor D/4 \rfloor})$$

**5. Security and Economic Properties**

* **Strict Linearity:** Since only one miner can spend the Lead UTXO of the previous block, the chain has a built-in mechanism to prevent branching, as the "right" to mine is a consumable resource in the UTXO set.  
* **Covenant Support:** Through forward visibility (v2), developers can create UTXOs that can only be spent to specific addresses or under specific economic conditions (e.g., inflation caps or cold-storage vaults).
