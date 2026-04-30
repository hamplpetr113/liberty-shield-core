//! Padding budget — controls cover-traffic padding cell issuance per epoch.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    Exhausted,
    ExceedsLimit,
}

pub struct PaddingBudget {
    per_epoch_limit: u64,
    remaining: u64,
    total_issued: u64,
    epochs: u64,
}

impl PaddingBudget {
    pub fn new(per_epoch_limit: u64) -> Self {
        Self {
            per_epoch_limit,
            remaining: per_epoch_limit,
            total_issued: 0,
            epochs: 0,
        }
    }

    pub fn request(&mut self, count: u64) -> Result<u64, BudgetError> {
        if count > self.per_epoch_limit {
            return Err(BudgetError::ExceedsLimit);
        }
        if count > self.remaining {
            return Err(BudgetError::Exhausted);
        }
        self.remaining -= count;
        self.total_issued += count;
        Ok(count)
    }

    pub fn advance_epoch(&mut self) {
        self.remaining = self.per_epoch_limit;
        self.epochs += 1;
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn total_issued(&self) -> u64 {
        self.total_issued
    }
    pub fn epochs(&self) -> u64 {
        self.epochs
    }
    pub fn per_epoch_limit(&self) -> u64 {
        self.per_epoch_limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PBU1: request within budget succeeds.
    #[test]
    fn pbu1_request_ok() {
        let mut b = PaddingBudget::new(10);
        assert_eq!(b.request(5), Ok(5));
    }

    // PBU2: remaining decrements after request.
    #[test]
    fn pbu2_remaining() {
        let mut b = PaddingBudget::new(10);
        b.request(3).unwrap();
        assert_eq!(b.remaining(), 7);
    }

    // PBU3: exhausted budget returns Exhausted.
    #[test]
    fn pbu3_exhausted() {
        let mut b = PaddingBudget::new(5);
        b.request(5).unwrap();
        assert_eq!(b.request(1), Err(BudgetError::Exhausted));
    }

    // PBU4: request exceeding per-epoch limit returns ExceedsLimit.
    #[test]
    fn pbu4_exceeds_limit() {
        let mut b = PaddingBudget::new(5);
        assert_eq!(b.request(10), Err(BudgetError::ExceedsLimit));
    }

    // PBU5: advance_epoch refills budget.
    #[test]
    fn pbu5_advance_epoch() {
        let mut b = PaddingBudget::new(10);
        b.request(10).unwrap();
        b.advance_epoch();
        assert_eq!(b.remaining(), 10);
    }

    // PBU6: total_issued accumulates across epochs.
    #[test]
    fn pbu6_total_issued() {
        let mut b = PaddingBudget::new(10);
        b.request(5).unwrap();
        b.advance_epoch();
        b.request(3).unwrap();
        assert_eq!(b.total_issued(), 8);
    }

    // PBU7: epochs counter increments.
    #[test]
    fn pbu7_epoch_counter() {
        let mut b = PaddingBudget::new(10);
        b.advance_epoch();
        b.advance_epoch();
        assert_eq!(b.epochs(), 2);
    }

    // PBU8: zero request always succeeds.
    #[test]
    fn pbu8_zero_request() {
        let mut b = PaddingBudget::new(10);
        b.request(10).unwrap();
        assert_eq!(b.request(0), Ok(0));
    }

    // PBU9: per_epoch_limit returns configured value.
    #[test]
    fn pbu9_limit() {
        let b = PaddingBudget::new(42);
        assert_eq!(b.per_epoch_limit(), 42);
    }

    // PBU10: multiple requests drain budget correctly.
    #[test]
    fn pbu10_multiple_requests() {
        let mut b = PaddingBudget::new(10);
        b.request(3).unwrap();
        b.request(3).unwrap();
        b.request(3).unwrap();
        assert_eq!(b.remaining(), 1);
    }
}
