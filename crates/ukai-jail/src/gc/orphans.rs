//! The orphan scan jail-macos.md §4.9 asks of `run` and `doctor`: before
//! doing anything else on macOS, look for attempts of this operator whose
//! custodians are both dead and whose end is not verified, and print one
//! line naming each and its recovery path. They never kill anything:
//! killing is `gc`'s. The scan never touches a receipt, the journal or
//! jail state, and a root it cannot read is skipped, not reported as a
//! failure: it is a diagnostic, not a reconciliation.

use super::host::{Host, Liveness, NativeHost};
use super::view::{
    guardian_with_identity, parse_guardian_identity, parse_guardian_record, parse_receipt,
    parse_state,
};
use super::{Options, RECORD_MAX};
use crate::records::Os;
use crate::state::{self, AttemptId};
use crate::supervisor::Context;

/// The line printed per attempt. The backticks are the command names.
fn line(id: &str, guardian_unknown: bool) -> String {
    if guardian_unknown {
        return format!(
            "ukai-jail: attempt {id} ended unverified: guardian identity is absent or unreadable; \
             reboot, then run `ukai-jail gc` (explicit abandonment after reboot may be needed \
             if boundary integrity was lost)"
        );
    }
    format!(
        "ukai-jail: attempt {id} ended unverified: run `ukai-jail gc` \
         (or `ukai-jail gc --abandon {id}` to release it)"
    )
}

/// Scans `<data>/attempts` (bounded like `gc`'s listing) and prints one
/// line per attempt of this operator whose custodians are both dead and
/// whose end is not verified; macOS only. Returns how many lines were
/// printed. Never fails, and never signals anything.
pub fn announce(ctx: &Context) -> usize {
    let identity = ctx.platform.state_identity();
    if identity.os != Os::Macos {
        return 0;
    }
    let Ok(data_dir) = state::data_dir(&ctx.env_settings, ctx.home.as_deref()) else {
        return 0;
    };
    let attempts = data_dir.join("attempts");
    let Ok(listing) = std::fs::read_dir(&attempts) else {
        return 0;
    };
    let host = NativeHost::new(ctx);
    let host_boot = host.identity().boot_id;
    let mut printed = 0;
    // Bounded like gc's listing (§14.2, S7); a diagnostic stops at the same
    // bound a reconciliation would.
    for entry in listing.flatten().take(Options::DEFAULT.max_entries) {
        let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|name| AttemptId::parse(name).ok())
        else {
            continue;
        };
        let dir = state::AttemptDir::new(&data_dir, &id);
        let Ok(Some(bytes)) = state::read_capped(&dir.state_path(), state::STATE_FILE_MAX) else {
            continue;
        };
        let Ok(state) = parse_state(&bytes, id.as_str()) else {
            continue;
        };
        // Birth times belong to the claiming host. Never interpret another
        // OS's owner using macOS liveness, including during a VM run.
        if state.os != identity.os.as_str() || state.arch != identity.arch {
            continue;
        }
        // An end a pass settled, verified or was released from needs no
        // operator, and `gc_finished` means gc costs this attempt nothing.
        if state.custody_released || state.gc_finished.is_some() || !state.gc_verified.is_empty() {
            continue;
        }
        // "Whose end is not verified": a receipt that proves the tree's end
        // settles the attempt; anything else (none written, corrupt,
        // unverified, lost integrity) leaves the operator to say.
        let receipt = state::read_capped(&dir.receipt_path(), RECORD_MAX)
            .ok()
            .flatten()
            .and_then(|bytes| parse_receipt(&bytes, id.as_str()).ok());
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.proves_tree_end())
        {
            continue;
        }
        // Custodian one: the recorded supervisor. Unknown liveness keeps
        // the attempt to itself (§14.2 keeps what it cannot read).
        let Some(owner) = &state.owner else {
            continue;
        };
        if !dead(&host.owner(owner)) {
            continue;
        }
        // A missing identity cannot establish a guardian dead in this
        // boot. The recovery line must not advise same-boot abandonment.
        let guardian = guardian_with_identity(
            state::read_capped(&dir.root().join(state::GUARDIAN_RECORD_NAME), RECORD_MAX)
                .ok()
                .flatten()
                .and_then(|bytes| parse_guardian_record(&bytes)),
            state::read_capped(&dir.root().join(state::GUARDIAN_IDENTITY_NAME), RECORD_MAX)
                .ok()
                .flatten()
                .and_then(|bytes| parse_guardian_identity(&bytes)),
        );
        if let Some(record) = &guardian
            && record.probeable()
            && !dead(&host.guardian(record))
        {
            continue;
        }
        let guardian_unknown = !guardian.as_ref().is_some_and(|record| record.probeable())
            && !host_boot
                .as_ref()
                .is_some_and(|boot| *boot != owner.boot_id);
        diag!("{}", line(id.as_str(), guardian_unknown));
        printed += 1;
    }
    printed
}

/// Whether a liveness answer establishes the custodian dead.
fn dead(liveness: &Liveness) -> bool {
    matches!(
        liveness,
        Liveness::Gone | Liveness::Reused | Liveness::Exited
    )
}

#[cfg(test)]
mod tests {
    use super::line;

    /// The §4.9 line names the attempt, `gc` and `gc --abandon`.
    #[test]
    fn the_line_names_the_attempt_and_both_commands() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        assert_eq!(
            line(id, false),
            format!(
                "ukai-jail: attempt {id} ended unverified: run `ukai-jail gc` \
                 (or `ukai-jail gc --abandon {id}` to release it)"
            )
        );
    }
}
