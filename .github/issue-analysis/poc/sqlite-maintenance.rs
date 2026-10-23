//! Component checks for Issue triage, using only synthetic marker files.

use std::cell::Cell;
use std::fs;

use asc_sqlite_kernel::maintenance::maintenance_marker_path;
use asc_sqlite_kernel::{MaintenanceOutcome, run_sqlite_maintenance_detailed};
use tempfile::TempDir;

fn observe(id: &str, marker: &str) -> MaintenanceOutcome {
    let directory = TempDir::new().expect("isolated synthetic directory");
    let db = directory.path().join("synthetic.db");
    fs::write(maintenance_marker_path(&db), marker).expect("synthetic marker");
    let calls = Cell::new(0);
    let outcome = run_sqlite_maintenance_detailed(&db, Some(86400.0), Some(200000.0), || {
        calls.set(calls.get() + 1);
        Ok(())
    });
    let observed = match &outcome {
        MaintenanceOutcome::Ran => {
            assert_eq!(calls.get(), 1);
            "Ran"
        }
        MaintenanceOutcome::NotDue => {
            assert_eq!(calls.get(), 0);
            "NotDue"
        }
        other => panic!("unexpected maintenance result: {other:?}"),
    };
    println!(
        "\nTRIAGE_CASE {{\"id\":\"{id}\",\"outcome\":\"{observed}\",\"callback_calls\":{}}}",
        calls.get()
    );
    outcome
}

#[test]
fn nan_marker() {
    // Record either behavior so a future fix is not reported as a failed PoC.
    observe("nan_marker", "NaN\n");
}

#[test]
fn expired_finite_marker() {
    assert_eq!(
        observe("expired_finite_marker", "1000\n"),
        MaintenanceOutcome::Ran
    );
}

#[test]
fn recent_finite_marker() {
    assert_eq!(
        observe("recent_finite_marker", "199999\n"),
        MaintenanceOutcome::NotDue
    );
}

#[test]
fn unparseable_marker() {
    assert_eq!(
        observe("unparseable_marker", "not a number\n"),
        MaintenanceOutcome::Ran
    );
}
