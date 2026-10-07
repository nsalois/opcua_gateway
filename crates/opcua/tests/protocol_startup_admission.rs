//! Compile the actual allocation-free firmware startup/connection module on host.
#[path = "../../../firmware/opta-m7/src/protocol_id_diagnostic.rs"]
mod startup;
use core::sync::atomic::Ordering;
use opta_opcua::{BuildInfo, ServerIdentity};

static INFO: BuildInfo = BuildInfo::new("Host admission", "1.0.0", "host", 0);

#[test]
fn actual_startup_is_finite_ignores_later_input_and_allocates_one_connection() {
    let identity = ServerIdentity::from_uid_words([1, 2, 3]);
    for recipe in 1..=3 {
        startup::M7_PROTOCOL_RECIPE_INPUT.store(recipe, Ordering::Relaxed);
        startup::consume_startup_input();
        // A running write to the input cannot change the latched recipe.
        startup::M7_PROTOCOL_RECIPE_INPUT.store(4, Ordering::Relaxed);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let threads: std::vec::Vec<_> = (1..=3)
            .map(|listener| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let server = startup::new_server(listener, identity, &INFO, 100 + listener);
                    (listener, server.diagnostic_initial_identifiers())
                })
            })
            .collect();
        barrier.wait();
        let results: std::vec::Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let seed = u32::MAX - 3 + recipe;
        let winners: std::vec::Vec<_> = results
            .iter()
            .filter(|(_, owners)| owners[0] == seed)
            .collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].1, [seed; 4]);
        for (listener, owners) in results.iter().filter(|(_, owners)| owners[0] != seed) {
            assert_eq!(*owners, [1, 1, 100 + listener, 1]);
        }
        let header: std::vec::Vec<_> = startup::M7_PROTOCOL_INITIAL_HEADER
            .0
            .iter()
            .map(|word| word.load(Ordering::Acquire))
            .collect();
        assert_eq!(
            header,
            [0x50524f54, recipe, winners[0].0, seed, seed, seed, seed, 1]
        );
        assert_eq!(
            startup::new_server(1, identity, &INFO, 321).diagnostic_initial_identifiers(),
            [1, 1, 321, 1]
        );
    }
    startup::M7_PROTOCOL_RECIPE_INPUT.store(0, Ordering::Relaxed);
    startup::consume_startup_input();
    assert_eq!(
        startup::new_server(1, identity, &INFO, 456).diagnostic_initial_identifiers(),
        [1, 1, 456, 1]
    );
    for invalid in [4, u32::MAX] {
        startup::M7_PROTOCOL_RECIPE_INPUT.store(invalid, Ordering::Relaxed);
        assert!(std::panic::catch_unwind(startup::consume_startup_input).is_err());
        assert_eq!(
            startup::new_server(1, identity, &INFO, 789).diagnostic_initial_identifiers(),
            [1, 1, 789, 1]
        );
    }
}
