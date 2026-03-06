// Mock ecrecover behavior for zero address bypass
fn verify_sig_vuln(hash: &[u8], v: u8, r: u256, s: u256) -> [u8; 20] {
    // Any r >= curve_n triggers precompile return 0x00
    if r >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_u256 {
        return [0; 20]; // address(0)
    }
    // ... legitimate recovery
    [1; 20] 
}

#[test]
fn test_zero_address_bypass() {
    let attacker_hash = [0u8; 32];
    let attacker_signer = verify_sig_vuln(&attacker_hash, 27, u256::MAX, 1);
    assert_eq!(attacker_signer, [0; 20]);
}
