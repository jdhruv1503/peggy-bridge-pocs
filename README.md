# Peggy Bridge Audit POCs

This repository contains Foundry POCs demonstrating high/medium severity vulnerabilities in the Peggy Bridge contract.

## Vulnerabilities
1. **PB-H01 (Zero-address bypass):** Allows quorum bypass by providing garbage signatures for zero-address validator slots.
2. **PB-M01 (Duplicate validator quorum inflation):** Allows a single validator key to satisfy quorum by appearing multiple times in the validator set.

## Running POCs
1. Ensure Foundry is installed.
2. Run tests:
   ```bash
   forge test
   ```

## Test Results
Tests demonstrate the bypass and inflation mechanisms by simulating `ecrecover` behavior and power calculation.
