pub fn constant_time_str_eq(left: &str, right: &str) -> bool {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let max_len = left_bytes.len().max(right_bytes.len());

    let mut diff = left_bytes.len() ^ right_bytes.len();
    for idx in 0..max_len {
        let left_byte = left_bytes.get(idx).copied().unwrap_or(0);
        let right_byte = right_bytes.get(idx).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_str_eq;

    #[test]
    fn constant_time_eq_accepts_identical_values() {
        assert!(constant_time_str_eq("secret-token", "secret-token"));
    }

    #[test]
    fn constant_time_eq_rejects_different_values() {
        assert!(!constant_time_str_eq("secret-token", "secret-token-2"));
        assert!(!constant_time_str_eq("secret-token", "secret-t0ken"));
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_str_eq("secret", "secret!"));
    }
}
