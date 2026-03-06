# Peggy Bridge Foundry Test Results

**Date:** 2026-02-24 UTC  
**Tool:** Foundry forge 1.5.1-stable  
**Contract:** PeggyMinimal.sol (faithful extraction of Peggy.sol logic)  
**Status: ALL 7 TESTS PASS — 0 FAILURES**

---

## Test Run Output

```
Ran 7 tests for test/PeggyVulnerabilities.t.sol:PeggyVulnerabilitiesTest

[PASS] test_FINDING01_ZeroAddressValidatorBypass() (gas: 179596)
Logs:
  ecrecover with out-of-range r returns: 0x0000000000000000000000000000000000000000
  === FINDING-01 CONFIRMED: Zero-address validator bypass SUCCEEDS ===
  alice power:        1,600,000,000
  address(0) power:   1,300,000,000  (counted via garbage ecrecover)
  Total counted:      2,900,000,000 > threshold 2,863,311,530
  bob's signature:    NOT provided (v=0 skip)

[PASS] test_FINDING01b_verifySigZeroAddressComparison() (gas: 12674)
Logs:
  verifySig(address(0), hash, 27, garbage_r, garbage_s) = true

[PASS] test_FINDING01c_DirectCheckValidatorSigsZeroAddress() (gas: 34538)
Logs:
  === FINDING-01c CONFIRMED: checkValidatorSignatures passes with zero-address bypass ===
  alice power   2,000,000,000
  zero-addr pwr 1,000,000,000 (garbage sig accepted)
  bob           ABSENT (v=0 skip)
  Total counted 3,000,000,000 > threshold 2,863,311,530

[PASS] test_FINDING02_SignatureMalleability() (gas: 136370)
Logs:
  Original sig recovers to alice? true
  Malleable sig recovers to alice? true
  === FINDING-02 CONFIRMED: Both canonical and malleable signatures accepted ===
  This breaks off-chain deduplication assuming signature uniqueness.

[PASS] test_FINDING03_DuplicateValidatorQuorumInflation() (gas: 176089)
Logs:
  === FINDING-03 CONFIRMED: Duplicate alice signature counted twice ===
  alice's two slots provide 3,000,000,000 power > threshold 2,863,311,530
  bob's signature NOT required -- alice alone controls the bridge

[PASS] test_FINDING04_VSilencingNoDetection() (gas: 190686)
Logs:
  === FINDING-04 CONFIRMED: v=0 silencing is undetectable on-chain ===
  Validator 5 (20% power) was silenced with v=0 -- contract does not care
  No event or counter tracks how many validators were v=0 silenced

[PASS] test_FINDING05_UnsortedPowersAccepted() (gas: 169413)
Logs:
  Power threshold:           2863311530
  === FINDING-05 CONFIRMED: Unsorted validator powers accepted ===
  Documentation says powers must be decreasing, contract does NOT enforce this.
  Bob (low power, first slot) absent; Alice (high power, second) alone suffices.

Suite result: ok. 7 passed; 0 failed; 0 skipped; finished in 5.11ms
```

---

## Finding Summary from Tests

| Test | Finding | Status | Severity |
|------|---------|--------|----------|
| test_FINDING01 | Zero-address validator allows malformed-sig quorum bypass | **CONFIRMED** | HIGH |
| test_FINDING01b | `verifySig(address(0), hash, 27, r_invalid, s)` = `true` | **CONFIRMED** | HIGH |
| test_FINDING01c | `checkValidatorSignatures` passes with zero-address bypass | **CONFIRMED** | HIGH |
| test_FINDING02 | Signature malleability — high-s not rejected | **CONFIRMED** | MEDIUM |
| test_FINDING03 | Duplicate validator address inflates quorum | **CONFIRMED** | HIGH |
| test_FINDING04 | v=0 silencing undetectable on-chain | **CONFIRMED** | MEDIUM |
| test_FINDING05 | Unsorted powers accepted (doc invariant violated) | **CONFIRMED** | MEDIUM |

---

## Technical Notes

### Why ecrecover returns address(0)
The EVM `ecrecover` precompile returns address(0) (empty bytes, zero-padded) when:
- `r >= secp256k1.n` (curve order) — mathematically out-of-range, no valid point
- `s >= secp256k1.n` — same
- `r = 0` or `s = 0`
- The recovered public key is the point at infinity
- `r` doesn't correspond to a valid x-coordinate on secp256k1

The tests use `r = type(uint256).max` which is `0xFFFF...FFFF > secp256k1.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`, guaranteeing address(0) recovery reliably for any hash.

### Preconditions for FINDING-01
The zero-address vulnerability requires `address(0)` to exist in the valset. This requires:
1. Cosmos `ValidateEthAddress` accepts `0x0000...0000` (confirmed in type analysis)
2. On-chain `Peggy.sol` has NO check against zero-address validators (confirmed)
3. A malicious or buggy orchestrator/governance creates such a valset

The attack surface exists at initialization, valset migration, or chain-level governance actions.

### Foundry project structure
```
foundry-test/
  src/PeggyMinimal.sol      # Faithful extraction of Peggy.sol verification logic
  test/PeggyVulnerabilities.t.sol  # All 7 PoC tests
  foundry.toml              # via_ir=true, optimizer=true
```
