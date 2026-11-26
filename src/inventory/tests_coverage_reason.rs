//! Coverage reason precedence for streamed redirects without a captured view.

use serde_json::json;

use super::tests::{BASE, build, opts, row, spec, view, write_scan};
use crate::route_discovery::DiscoveredRoute;

#[tokio::test]
async fn explicit_redirect_outranks_attempted_no_view_in_either_order() {
    for reverse in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut document = row("GET", "/scans/42", Some(200), None, None);
        document["request"]["headers"] = json!({"Sec-Fetch-Dest": "document"});
        write_scan(
            dir.path(),
            &spec(vec![view("view_0001", "/sessions/7", vec![])]),
            Some(&[]),
            &[document],
        );
        let mut items = vec![
            json!({
                "kind": "seeded_route", "target": format!("{BASE}/scans/42"),
                "reason": "seed_route_attempted_without_view",
            }),
            json!({
                "kind": "seeded_route", "target": format!("{BASE}/scans/42"),
                "reason": "seed_route_redirected",
                "context": format!("final_url={BASE}/sessions/7"),
            }),
        ];
        if reverse {
            items.reverse();
        }
        items.push(json!({
            "kind": "seeded_route", "target": format!("{BASE}/pending"),
            "reason": "seed_route_attempted_without_view",
        }));
        std::fs::write(
            dir.path().join("coverage-gaps.json"),
            json!({"items": items}).to_string(),
        )
        .unwrap();
        let mut options = opts();
        options.discovered_routes = ["/scans/:scanId", "/sessions/:sessionId", "/pending"]
            .into_iter()
            .map(|path| DiscoveredRoute {
                path: path.into(),
                kind: "page".into(),
                ..Default::default()
            })
            .collect();
        let inv = build(dir.path(), &options).await;
        let scan = inv
            .routes
            .iter()
            .find(|r| r.route == "/scans/:scanId")
            .unwrap();
        assert!(!scan.visited);
        assert_eq!(scan.status, Some(200));
        assert_eq!(scan.unvisited_reason.as_deref(), Some("redirects"));
        assert_eq!(
            inv.coverage.unvisited_by_reason.get("redirects"),
            Some(&vec!["/scans/:scanId".to_string()])
        );
        assert_eq!(
            inv.coverage
                .unvisited_by_reason
                .get("attempted, no view captured"),
            Some(&vec!["/pending".to_string()])
        );
        assert!(
            inv.routes
                .iter()
                .any(|r| r.route == "/sessions/:sessionId" && r.visited)
        );
    }
}
