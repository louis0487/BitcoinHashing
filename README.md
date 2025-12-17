# Bitcoin Hashing Hardware Accelerator (SystemVerilog)

**Authors:** Bing-You Yu & Louis Lin  
**Course:** ECE 111 - Advanced Digital Design Project (UCSD)

## 📖 Project Overview
This project implements a hardware accelerator for **Bitcoin Hashing** using **SystemVerilog**. The core algorithm is **Double SHA-256** (`SHA256(SHA256(Header))`), which is the fundamental mechanism used in Bitcoin mining for data integrity and block verification.

The project explores the trade-offs between performance and resource usage by implementing two distinct hardware architectures on an FPGA:
1.  **Min-Delay Design (Performance Optimized):** A fully parallelized architecture.
2.  **Area-Delay Optimization Design:** A serialized, resource-efficient architecture.

## 🚀 Architectures

### 1. Min-Delay Design (Fully Parallel)
* **Strategy:** Optimized for maximum speed using SIMD (Single Instruction, Multiple Data) techniques.
* **Mechanism:** Instantiates **16 separate SHA-256 computational units** to process 16 nonces simultaneously.
* **Pros:** Extremely low latency (fewer cycles to complete a batch).
* **Cons:** High resource consumption (ALUTs and Registers).

### 2. Area-Delay Optimization Design (Serial)
* **Strategy:** Optimized to balance chip area and processing delay.
* **Mechanism:** Uses a **single SHA-256 computational unit**. It iterates through the 16 nonces sequentially using a counter (`nonce_ctr`).
* **Pros:** Significantly lower area usage (approx. 10x smaller).
* **Cons:** Higher latency due to serial processing.

## ⚙️ How It Works (FSM & Logic)

Both designs follow a specialized Finite State Machine (FSM) to handle the Bitcoin Block Header hashing process efficiently:

1.  **READ:** Loads the 19-word (608-bit) Block Header from memory.
2.  **PHASE 1 (Midstate Calculation):** * Since the first 512 bits (Block 1) of the header are identical for all nonces, this phase calculates the SHA-256 hash of Block 1 **only once**. 
    * The result ("Midstate") is saved to `phase1_hashes` and reused, saving 64 calculation steps for every nonce.
3.  **PHASE 2 (First Hash Completion):** * Computes the hash of Block 2 (which contains the varying `nonce`).
    * *Min-Delay:* All 16 nonces computed in parallel.
    * *Area-Delay:* Computes nonces 0-15 sequentially in a loop.
4.  **PHASE 3 (Double Hash):** * Takes the 256-bit result from Phase 2 and applies SHA-256 again (`SHA256(Result_Phase2)`).
    * Padding is applied to fit the standard block size.
5.  **WRITE:** Outputs the final 16 hash values to memory.

## 📊 Performance Results

The following data compares the resource usage and timing analysis for both designs (Target Device: Arria II GX EP2AGX45DF2915).

| Metric | Min-Delay Design (Parallel) | Area-Delay Opt Design (Serial) | Impact |
| :--- | :--- | :--- | :--- |
| **ALUTs** | **29,281** | **2,734** | **~90% Reduction** |
| **Registers** | 14,499 | 2,215 | Significant Reduction |
| **Fmax (MHz)** | 40.62 MHz | 109.93 MHz | 2.7x Frequency Increase |
| **Total Cycles** | 236 | 2,186 | Serial is slower |
| **Delay (µs)** | 5.81 µs | 19.89 µs | Parallel is ~3.4x faster |
| **Area × Delay** | **254.36** | **98.41** | **Optimization Winner** |

*Data Source: Final Project Summary*

### Key Takeaway
The **Area-Delay Optimization** design successfully reduced the Area-Delay product from 254.36 to 98.41. While the serial approach takes more clock cycles, the massive reduction in logic utilization (ALUTs) and the increase in maximum frequency (Fmax) make it a more efficient design for resource-constrained FPGAs.

## 🛠 Tools Used
* **Language:** SystemVerilog
* **Synthesis/Simulation:** Intel Quartus Prime, ModelSim
* **Hardware:** Family: FPGA (Arria II GX)  Device: EP2AGX45DF29I5

## 📂 File Structure
* `bitcoin_hash_areadelay_optimization.sv`: Area and Delay optimization version of Top-level module implementing the FSM and hashing logic.
* `bitcoin_hash_mindelay.sv`: Delay only optimization version of Top-level module implementing the FSM and hashing logic.
* `simplified_sha256.sv`: Helper module for standard SHA-256 operations.
* `tb_bitcoin_hash.sv`: Testbench for verifying hash correctness against expected output.
