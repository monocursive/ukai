//! Exact guest-native policy carry. Host paths and guest paths stay separate.
use super::*;
use crate::guest_program::GuestProgram;

pub(super) fn launch(
    snapshot: &PolicySnapshot,
    program: &GuestProgram,
    guest: bool,
) -> Result<crate::launch_profile::LaunchProfile, String> {
    let text = crate::launch_profile::bundled_profile(&program.entry.alias)
        .ok_or("guest program has no bundled launch profile")?;
    if crate::guest_program::sha256(text.as_bytes()) != program.entry.profile_sha256 {
        return Err("guest catalog and bundled launch profile differ".into());
    }
    let mut parsed = crate::launch_profile::parse_with(
        text,
        &program.entry.alias,
        crate::launch_profile::LaunchSource::Bundled,
        None,
        Some(b"/run/ukai-vm/native-config"),
    )
    .map_err(|error| error.message)?;
    let declared = snapshot
        .launch
        .as_ref()
        .ok_or("guest native launch is absent")?;
    if declared.credentials.len() != 1 || parsed.program_root != program.entry.program_root {
        return Err("guest native launch needs exactly one selected credential and the catalog program root".into());
    }
    let selected = &declared.credentials[0];
    if !parsed.credentials_one_of.contains(&selected.id) {
        return Err("selected credential is outside the bundled source preference".into());
    }
    parsed
        .credentials
        .retain(|credential| credential.id == selected.id);
    if parsed.credentials.len() != 1 {
        return Err("selected credential is absent from bundled profile".into());
    }
    let credential = &mut parsed.credentials[0];
    if credential.mode != CredentialMode::Vault {
        return Err("guest native launch requires vault mode".into());
    }
    let policy = credential
        .vault
        .as_mut()
        .ok_or("guest native vault policy is absent")?;
    if policy.binaries != [crate::vault::PROGRAM_TOKEN] || policy.refresh.is_some() {
        return Err("guest native profile requires exactly @program and no refresh".into());
    }
    policy.binaries = vec![program.executable.as_str().to_owned()];
    if !guest {
        credential.source = selected.source.clone();
    }
    parsed.state = crate::launch_profile::StateKind::Attempt;
    Ok(parsed)
}

pub(super) fn refusal(plan: &PlanRequest) -> Option<(String, String)> {
    let program = plan.guest_program.as_ref()?;
    let snapshot = &plan.snapshot;
    let result = (|| {
        if snapshot.profile != ProfileName::Agent {
            return Err(NotCarried::new(
                "profile",
                "guest native execution requires the agent profile",
            ));
        }
        let launch = launch(snapshot, program, false).map_err(|e| NotCarried::new("launch", e))?;
        let expected = resolve_side(
            snapshot,
            &Side::Host,
            snapshot.roots.workspace.as_bytes(),
            Some(&launch),
            Some(program),
        )
        .map_err(|e| NotCarried::new("policy", e))?;
        compare_carried(snapshot, &expected)
    })();
    result.err().map(|error| (error.reason(), error.message()))
}

pub(super) fn vault(plan: &PreparedPlan) -> Result<VaultLaunch, JailError> {
    let program = plan
        .request
        .guest_program
        .as_ref()
        .ok_or_else(|| refused("guest identity missing"))?;
    if plan.launch.is_some()
        || plan.proxy.is_some()
        || !plan.pinned_roots.is_empty()
        || !plan.exec_pins.is_empty()
    {
        return Err(refused(
            "guest native preparation received local state, proxy or executable authority",
        ));
    }
    let parsed = launch(&plan.request.snapshot, program, true).map_err(refused)?;
    let handoff = plan
        .guest_launch
        .as_ref()
        .ok_or_else(|| refused("guest source-only handoff missing"))?;
    let declared = &plan
        .request
        .snapshot
        .launch
        .as_ref()
        .ok_or_else(|| refused("guest launch absent"))?
        .credentials;
    if handoff.sources.len() != 1 || declared.len() != 1 {
        return Err(refused("guest launch source selection differs from policy"));
    }
    let source = &handoff.sources[0];
    if source.id != declared[0].id || Some(&source.policy) != declared[0].vault.as_ref() {
        return Err(refused("guest source policy differs from resolved policy"));
    }
    let value = source.value().map_err(refused)?;
    Ok(VaultLaunch {
        declaration: None,
        parsed: Some(parsed),
        secrets: vec![protocol::SecretEntry {
            id: source.id.clone(),
            data: protocol::encode_data(&value),
        }],
    })
}

pub(super) fn intent(
    plan: &PreparedPlan,
    program: &GuestProgram,
    policy_digest: &str,
) -> Result<protocol::GuestLaunchIntent, JailError> {
    if plan.argv.first().map(Vec::as_slice) != Some(program.executable.as_bytes()) {
        return Err(refused(
            "guest resolved argv differs from its catalog executable",
        ));
    }
    let suffix = &plan.argv[1..];
    let request: Vec<Vec<u8>> = std::iter::once(program.entry.alias.as_bytes().to_vec())
        .chain(suffix.iter().cloned())
        .collect();
    let credential = plan
        .request
        .snapshot
        .launch
        .as_ref()
        .and_then(|launch| launch.credentials.first())
        .ok_or_else(|| refused("guest selected credential absent"))?;
    Ok(protocol::GuestLaunchIntent {
        schema: protocol::NATIVE_PROGRAM_CONTRACT.into(),
        catalog_sha256: program.catalog_sha256.clone(),
        entry_id: program.entry.id.clone(),
        launch_name: program.entry.alias.clone(),
        profile_sha256: program.entry.profile_sha256.clone(),
        state: "attempt".into(),
        selected_credential_id: credential.id.clone(),
        argv_suffix: suffix
            .iter()
            .map(|value| protocol::encode_data(value))
            .collect(),
        request_argv_digest: crate::canonical::argv_digest(&request),
        resolved_argv_digest: crate::canonical::argv_digest(&plan.argv),
        expected_policy_digest: policy_digest.into(),
    })
}

pub(super) fn binding(
    intent: &protocol::GuestLaunchIntent,
    program: &GuestProgram,
) -> protocol::NativeProgramBinding {
    protocol::NativeProgramBinding {
        catalog_sha256: intent.catalog_sha256.clone(),
        entry_id: intent.entry_id.clone(),
        profile_sha256: intent.profile_sha256.clone(),
        executable_sha256: program.entry.executable_sha256.clone(),
        selected_credential_id: intent.selected_credential_id.clone(),
        state: intent.state.clone(),
        request_argv_digest: intent.request_argv_digest.clone(),
        resolved_argv_digest: intent.resolved_argv_digest.clone(),
        policy_digest: intent.expected_policy_digest.clone(),
    }
}

/// Preserve the bundled grant layer and carry only the additional occurrences.
/// Missing bundled grants remain missing from the final snapshot comparison and
/// therefore refuse; they cannot be silently reintroduced by a project shrink.
pub(super) fn additional_hosts(
    snapshot: &PolicySnapshot,
    launch: &crate::launch_profile::LaunchProfile,
) -> Vec<String> {
    let mut extra = guest_allow_hosts(&snapshot.network);
    for original in &launch.network_allow {
        if let Ok(rule) = crate::network::HostRule::parse(original)
            && let Some(index) = extra.iter().position(|value| {
                crate::network::HostRule::parse(value).is_ok_and(|candidate| {
                    candidate.canonical() == rule.canonical()
                        && candidate.explicit_port == rule.explicit_port
                })
            })
        {
            extra.remove(index);
        }
    }
    extra
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt as _;

    pub(crate) fn input(key: &str) -> String {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../vm/fixtures/guest-native-profile-inputs.json"
        ))
        .unwrap();
        fixture[key].as_str().unwrap().to_owned()
    }

    pub(crate) fn context() -> (
        tempfile::TempDir,
        crate::supervisor::Context,
        crate::cli::PolicyArgs,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for name in [
            "work",
            "home",
            "config",
            "config/credentials",
            "data",
            "install",
            "install/image",
        ] {
            let path = root.join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let alias = input("alias");
        let source = root
            .join("config/credentials")
            .join(input("primary_credential_id"));
        std::fs::write(&source, b"synthetic-never-provider-token").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fixture = include_bytes!("../../../../vm/fixtures/guest-program-catalog.json");
        let mut catalog =
            crate::guest_program::Catalog::parse(fixture, &crate::guest_program::sha256(fixture))
                .unwrap();
        let entry = &mut catalog.entries[0];
        entry.alias = alias.clone();
        entry.install_root = format!("/opt/ukai/programs/{alias}/1.2.3");
        entry.executable = format!("{}/{alias}", entry.install_root);
        entry.argv_prefix = vec![entry.executable.clone()];
        entry.tree[1].path = alias.clone();
        entry.profile_sha256 = crate::guest_program::sha256(
            crate::launch_profile::bundled_profile(&input("alias"))
                .unwrap()
                .as_bytes(),
        );
        let bytes = serde_json::to_vec(&catalog).unwrap();
        let digest = crate::guest_program::sha256(&bytes);
        std::fs::write(root.join("install/image/guest-program-catalog.json"), bytes).unwrap();
        let platform = VmPlatform {
            data_dir: root.join("data"),
            install: Install {
                root: root.join("install"),
                manifest: image::ImageManifest {
                    source_sha256: Default::default(),
                    status: "prepared".into(),
                    disk_sha256: "d".repeat(64),
                    helper_sha256: "a".repeat(64),
                    custodian_sha256: "c".repeat(64),
                    seed_sha256: "e".repeat(64),
                    guest_program_catalog_sha256: Some(digest),
                },
            },
        };
        let argv = [
            "ukai-jail",
            "run",
            "--from-path",
            "--launch",
            &alias,
            "--workspace",
            root.join("work").to_str().unwrap(),
            "--state",
            "attempt",
            "--terminal",
            "detach",
            "--limit",
            "wall=60s",
            "--",
            "-p",
            "hello",
        ]
        .map(str::to_owned);
        let crate::cli::Command::Run(args) = crate::cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        let context = crate::supervisor::Context {
            platform: Box::new(platform),
            cwd: root.join("work"),
            home: Some(root.join("home")),
            env_settings: crate::config::EnvSettings {
                config_dir: Some(root.join("config")),
                data_dir: Some(root.join("data")),
                ..Default::default()
            },
            env_lookup: Box::new(|name| {
                assert_ne!(name, "PATH", "guest program resolution consulted host PATH");
                (name == "LANG").then(|| b"C.UTF-8".to_vec())
            }),
        };
        (dir, context, args.policy)
    }

    #[test]
    fn guest_native_plan_preserves_bundle_and_never_opens_host_program() {
        let (_dir, context, args) = context();
        let plan = crate::supervisor::resolve_plan(&context, &args).unwrap();
        assert!(plan.program.is_none());
        let guest = plan.guest_program.as_ref().unwrap();
        assert_eq!(
            guest.executable.as_str(),
            format!("/opt/ukai/programs/{0}/1.2.3/{0}", input("alias"))
        );
        let launch = plan.resolved.snapshot.launch.as_ref().unwrap();
        assert_eq!(launch.credentials.len(), 1);
        assert_eq!(launch.credentials[0].id, input("primary_credential_id"));
        assert_eq!(
            launch.credentials[0].vault.as_ref().unwrap().binaries,
            [guest.executable.as_str()]
        );
        let encoded = serde_json::to_string(&plan.resolved.snapshot).unwrap();
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../vm/fixtures/guest-native-profile-inputs.json"
        ))
        .unwrap();
        for key in fixture["required_env"].as_array().unwrap() {
            assert!(encoded.contains(key.as_str().unwrap()));
        }
        assert!(
            plan.resolved
                .snapshot
                .network
                .allow
                .iter()
                .any(|host| host.contains(&input("secondary_host")))
        );
        assert!(
            plan.resolved
                .provenance
                .iter()
                .any(|entry| entry.key.contains(&input("secondary_credential_id")))
        );
    }

    #[test]
    fn guest_source_capture_is_deadline_bound_and_initial_replacement_revokes() {
        let (_dir, context, args) = context();
        let plan = crate::supervisor::resolve_plan(&context, &args).unwrap();
        let launch = plan.resolved.snapshot.launch.as_ref().unwrap();
        let program = plan.guest_program.as_ref().unwrap();
        let expired =
            crate::credentials::stage_guest_within(launch, program, &[], &|| Duration::ZERO);
        assert!(expired.is_err());
        let (handoff, staged) =
            crate::credentials::stage_guest_within(launch, program, &[], &|| {
                Duration::from_secs(1)
            })
            .unwrap();
        assert!(staged.vault.is_none());
        assert!(staged.bind.is_none());
        assert!(staged.record.never_staged);
        assert_eq!(staged.source, handoff.sources[0].identity());
        let path = context
            .env_settings
            .config_dir
            .as_ref()
            .unwrap()
            .join("credentials")
            .join(input("primary_credential_id"));
        std::fs::rename(&path, path.with_extension("old")).unwrap();
        std::fs::write(&path, b"synthetic-never-provider-token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            handoff.sources[0].value().is_err(),
            "same bytes at a new generation became transport authority"
        );
        assert!(
            !context
                .env_settings
                .data_dir
                .as_ref()
                .unwrap()
                .join("attempts")
                .exists()
        );
    }

    #[test]
    fn guest_native_project_narrowing_refuses_before_source_loading() {
        for policy in [
            format!(
                "[jail.filesystem]\ndeny_read = [\"/opt/ukai/programs/{}/1.2.3\"]\n",
                input("alias")
            ),
            format!("[jail.network]\nallow = [\"{}\"]\n", input("primary_host")),
        ] {
            let (_dir, context, args) = context();
            std::fs::write(context.cwd.join("ukai.toml"), policy).unwrap();
            let error = match crate::supervisor::resolve_plan(&context, &args) {
                Ok(_) => panic!("narrowing silently dropped"),
                Err(error) => error,
            };
            assert!(error.message.contains("not-carried"), "{error}");
            assert!(
                !context
                    .env_settings
                    .data_dir
                    .as_ref()
                    .unwrap()
                    .join("attempts")
                    .exists()
            );
        }
    }

    #[test]
    fn guest_native_requires_explicit_attempt_and_unchanged_bundle() {
        let (_dir, context, mut args) = context();
        args.state = None;
        assert!(crate::supervisor::resolve_plan(&context, &args).is_err());
        args.state = Some(crate::cli::StateChoice::Attempt);
        args.selection.profile = Some("tool".into());
        assert!(crate::supervisor::resolve_plan(&context, &args).is_err());
        assert!(
            !context
                .env_settings
                .data_dir
                .as_ref()
                .unwrap()
                .join("attempts")
                .exists()
        );
        args.selection.profile = None;
        let launch_dir = context
            .env_settings
            .config_dir
            .as_ref()
            .unwrap()
            .join("launch");
        std::fs::create_dir(&launch_dir).unwrap();
        let path = launch_dir.join(format!("{}.toml", input("alias")));
        std::fs::write(
            &path,
            crate::launch_profile::bundled_profile(&input("alias")).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(crate::supervisor::resolve_plan(&context, &args).is_err());
    }
}
