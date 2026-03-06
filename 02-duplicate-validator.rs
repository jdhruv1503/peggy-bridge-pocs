struct ValidatorSet {
    validators: Vec<[u8; 20]>,
    powers: Vec<u64>,
}

impl ValidatorSet {
    fn calculate_power(&self, signatures: &Vec<[u8; 64]>) -> u64 {
        let mut total_power = 0;
        for i in 0..self.validators.len() {
            // No uniqueness check on self.validators
            // Signature reuse allowed
            total_power += self.powers[i];
        }
        total_power
    }
}

#[test]
fn test_duplicate_validator_inflation() {
    let vs = ValidatorSet {
        validators: vec![[1; 20], [1; 20]],
        powers: vec![100, 100],
    };
    let sigs = vec![[0; 64], [0; 64]];
    assert_eq!(vs.calculate_power(&sigs), 200);
}
