use super::*;

#[test]
fn export_confines_outputs_in_the_selected_root_namespace() {
    let parent = tempfile::TempDir::new().unwrap();
    let selected = parent.path().join("private");
    let root = OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
    for base in [selected.clone(), std::fs::canonicalize(&selected).unwrap()] {
        let (_, _, output) = provider_export_paths(&base, &base.join("new/provider.json")).unwrap();
        assert_eq!(output.as_str(), "new/provider.json");
        assert!(provider_export_paths(&base, &parent.path().join("outside.json")).is_err());
        assert!(provider_export_paths(&base, &base.join("../outside.json")).is_err());
        assert!(provider_export_paths(&base, &base).is_err());
    }
    root.write_atomic(&relative("keep").unwrap(), b"preserved")
        .unwrap();
    assert_eq!(
        root.read_file(&relative("keep").unwrap(), 32).unwrap(),
        b"preserved"
    );
}
