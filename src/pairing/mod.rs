pub mod auth;
#[cfg_attr(not(feature = "test-hooks"), allow(dead_code))]
pub mod codec;
pub mod store;

#[cfg(test)]
pub(crate) struct BoundedBarrier {
    parties: usize,
    state: std::sync::Mutex<(usize, usize)>,
    cv: std::sync::Condvar,
}

#[cfg(test)]
impl BoundedBarrier {
    pub(crate) fn new(parties: usize) -> Self {
        Self {
            parties,
            state: std::sync::Mutex::new((0, 0)),
            cv: std::sync::Condvar::new(),
        }
    }

    pub(crate) fn wait(&self, label: &str) {
        let mut guard = self.state.lock().unwrap();
        let generation = guard.1;
        guard.0 += 1;
        if guard.0 >= self.parties {
            guard.0 = 0;
            guard.1 = generation.wrapping_add(1);
            self.cv.notify_all();
            return;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while guard.1 == generation {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "pairing test barrier timed out after 15s: {label}"
            );
            let (next, timeout) = self.cv.wait_timeout(guard, remaining).unwrap();
            guard = next;
            if timeout.timed_out() && guard.1 == generation {
                panic!("pairing test barrier timed out after 15s: {label}");
            }
        }
    }
}
