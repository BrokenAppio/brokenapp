use std::{fs, path::Path};

use anyhow::Result;

#[test]
fn runtime_fixture_contains_production_regression_targets() -> Result<()> {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runtime-site");
    let index = fs::read_to_string(fixture_dir.join("index.html"))?;
    let account = fs::read_to_string(fixture_dir.join("account.html"))?;

    for expected in [
        "id=\"working-button\"",
        "id=\"dead-button\"",
        "id=\"open-modal\"",
        "role=\"tablist\"",
        "id=\"network-error-button\"",
        "id=\"cors-button\"",
    ] {
        assert!(
            index.contains(expected),
            "runtime fixture index.html is missing regression target {expected}"
        );
    }

    assert!(
        index.contains("img src=\"/missing-product.png\""),
        "runtime fixture should keep a controlled broken image request"
    );
    assert!(
        account.contains("form action=\"/api/profile\" method=\"post\""),
        "runtime fixture account page should keep a controlled form endpoint"
    );

    Ok(())
}
