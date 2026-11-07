use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        usage();
        std::process::exit(2);
    };
    if command == "--help" {
        usage();
        return;
    }
    if command == "write-provider-manifest" {
        let options = match provider_options(args.collect()) {
            Some(options) => options,
            None => {
                eprintln!(
                    "submission fixture tool requires data root, two configs, and an output path"
                );
                std::process::exit(2);
            }
        };
        let result = dissect3d_engine::write_submission_provider_manifest(
            &options["--data-root"],
            &options["--config-a"],
            &options["--config-b"],
            &options["--output"],
        );
        if let Err(error) = result {
            eprintln!("submission fixture tool failed: {}", error.safe_code());
            std::process::exit(1);
        }
        return;
    }
    let Some(flag) = args.next() else {
        eprintln!("submission fixture tool requires --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    };
    let Some(path) = args.next() else {
        eprintln!("submission fixture tool requires an absolute data root");
        std::process::exit(2);
    };
    if flag != "--data-root" || args.next().is_some() {
        eprintln!("submission fixture tool accepts one --data-root ABSOLUTE_PATH option");
        std::process::exit(2);
    }
    let path = PathBuf::from(path);
    let result = match command.to_str() {
        Some("prepare") => dissect3d_engine::prepare_submission_fixture(&path),
        Some("probe-cpu") => dissect3d_engine::probe_submission_fixture(&path),
        _ => {
            usage();
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("submission fixture tool failed: {}", error.safe_code());
        std::process::exit(1);
    }
}

fn usage() {
    println!(
        "Usage: submission_fixture_tool prepare --data-root ABSOLUTE_PATH\n\
         Internal probe: submission_fixture_tool probe-cpu --data-root ABSOLUTE_PATH\n\
         Provider export: submission_fixture_tool write-provider-manifest --data-root ABS_ROOT --config-a ABS_CONFIG --config-b ABS_CONFIG --output ABS_MANIFEST"
    );
}

fn provider_options(args: Vec<std::ffi::OsString>) -> Option<BTreeMap<String, PathBuf>> {
    let mut values = BTreeMap::new();
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let flag = flag.into_string().ok()?;
        if !matches!(
            flag.as_str(),
            "--data-root" | "--config-a" | "--config-b" | "--output"
        ) {
            return None;
        }
        let value = PathBuf::from(args.next()?);
        if !value.is_absolute() || values.insert(flag, value).is_some() {
            return None;
        }
    }
    (values.len() == 4).then_some(values)
}
