//! Seccomp deny-list compilation (spec §7.1 layer 5).
//!
//! The deny list is the *only* seccomp layer: the filter returns `EPERM` for
//! each listed syscall and allows everything else. It is applied by the
//! `softfig-sandbox-init` shim, chosen over bwrap `--seccomp <fd>` so the bwrap
//! argv stays a pure, deterministic `Vec<String>` with no inherited FD number.

use std::collections::BTreeMap;
use std::error::Error;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// Map a lowercase syscall name from the deny list to its number on the current
/// target. Returns `None` for a name this target doesn't expose, which is then
/// skipped (a name we cannot resolve cannot be denied, and failing open on the
/// deny side is strictly better than denying everything).
fn syscall_number(name: &str) -> Option<i64> {
    let nr = match name {
        "ptrace" => libc::SYS_ptrace,
        "keyctl" => libc::SYS_keyctl,
        "add_key" => libc::SYS_add_key,
        "bpf" => libc::SYS_bpf,
        "perf_event_open" => libc::SYS_perf_event_open,
        "userfaultfd" => libc::SYS_userfaultfd,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "mount" => libc::SYS_mount,
        "pivot_root" => libc::SYS_pivot_root,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "kexec_load" => libc::SYS_kexec_load,
        "kexec_file_load" => libc::SYS_kexec_file_load,
        "personality" => libc::SYS_personality,
        "request_key" => libc::SYS_request_key,
        "fsopen" => libc::SYS_fsopen,
        "fsconfig" => libc::SYS_fsconfig,
        "fsmount" => libc::SYS_fsmount,
        "fspick" => libc::SYS_fspick,
        "move_mount" => libc::SYS_move_mount,
        "open_tree" => libc::SYS_open_tree,
        "mount_setattr" => libc::SYS_mount_setattr,
        _ => return None,
    };
    Some(nr)
}

/// The x32 ABI flag on an x86_64 syscall number. A kernel built with
/// `CONFIG_X86_X32_ABI` reports x32 calls under the x86_64 audit arch with this
/// bit set, so a filter that only lists the plain numbers never sees them.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// x32's own number for `ptrace`; unlike the calls above (shared numbers with the
/// x32 bit set) it has a dedicated entry in the x32 table.
#[cfg(target_arch = "x86_64")]
const X32_SYS_PTRACE: i64 = X32_SYSCALL_BIT | 521;

/// Every syscall number the deny list covers on this target: each name's
/// native number, plus (x86_64) its x32 alias, which would otherwise bypass the
/// filter.
fn denied_numbers(deny: &[String]) -> Vec<i64> {
    let mut nrs = Vec::new();
    for name in deny {
        if let Some(nr) = syscall_number(name) {
            nrs.push(nr);
            #[cfg(target_arch = "x86_64")]
            {
                nrs.push(nr | X32_SYSCALL_BIT);
                if nr == libc::SYS_ptrace {
                    nrs.push(X32_SYS_PTRACE);
                }
            }
        }
    }
    nrs
}

/// Build a seccomp BPF program that returns `EPERM` for every listed syscall
/// and allows everything else. Unknown names are skipped.
pub fn build_seccomp_filter(deny: &[String]) -> Result<BpfProgram, Box<dyn Error + Send + Sync>> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for nr in denied_numbers(deny) {
        // An empty rule vector matches the syscall regardless of arguments.
        rules.entry(nr).or_default();
    }

    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| format!("unsupported architecture {}: {e}", std::env::consts::ARCH))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // default: allow everything else
        SeccompAction::Errno(libc::EPERM as u32), // on match: EPERM
        arch,
    )?;

    Ok(filter.try_into()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_resolve_to_distinct_syscall_numbers() {
        let ptrace = syscall_number("ptrace").expect("ptrace resolves");
        let bpf = syscall_number("bpf").expect("bpf resolves");
        let mount = syscall_number("mount").expect("mount resolves");
        assert_ne!(ptrace, bpf);
        assert_ne!(bpf, mount);
        assert_eq!(ptrace, libc::SYS_ptrace);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn deny_list_covers_the_x32_aliases() {
        let deny = vec!["io_uring_setup".to_string(), "ptrace".to_string()];
        let nrs = denied_numbers(&deny);
        assert!(nrs.contains(&libc::SYS_io_uring_setup));
        assert!(nrs.contains(&(libc::SYS_io_uring_setup | X32_SYSCALL_BIT)));
        assert!(nrs.contains(&X32_SYS_PTRACE));
    }

    #[test]
    fn new_mount_api_and_request_key_resolve() {
        for name in [
            "request_key", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree",
            "mount_setattr",
        ] {
            assert!(syscall_number(name).is_some(), "{name} must resolve");
        }
    }

    #[test]
    fn unknown_names_are_skipped() {
        assert_eq!(syscall_number("definitely_not_a_syscall"), None);
    }

    #[test]
    fn filter_compiles_for_this_arch() {
        let deny: Vec<String> =
            ["ptrace", "bpf", "keyctl", "mount"].iter().map(|s| s.to_string()).collect();
        let program = build_seccomp_filter(&deny).expect("filter compiles");
        // A compiled filter is never empty (arch check + return instructions).
        assert!(!program.is_empty());
    }

    #[test]
    fn empty_deny_list_still_compiles_to_a_noop() {
        let program = build_seccomp_filter(&[]).expect("empty deny compiles");
        assert!(!program.is_empty());
    }
}
