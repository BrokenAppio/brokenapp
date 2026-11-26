use std::collections::BTreeMap;

use crate::explorer::{CoverageGapKind, CoverageGapReport};

fn template_hint(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() || trimmed == "scan_loop" {
        return None;
    }
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with('/')
        || trimmed.starts_with('#')
    {
        return crate::explorer::template_sampler::url_to_template_path(trimmed);
    }
    None
}

pub fn render_markdown(report: &CoverageGapReport) -> String {
    let mut out = String::new();
    out.push_str("# Coverage Gap Report\n\n");
    out.push_str(&format!("- Total gaps: {}\n", report.summary.total));
    if report.summary.by_reason.is_empty() {
        out.push('\n');
    } else {
        out.push_str("- By reason:\n");
        for (reason, count) in &report.summary.by_reason {
            out.push_str(&format!("  - {}: {}\n", reason, count));
        }
        out.push('\n');
    }

    if report.items.is_empty() {
        out.push_str("_No uncovered routes/interactions were recorded._\n");
        return out;
    }

    let mut by_reason: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_template: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();

    for item in &report.items {
        let reason = item.reason.trim().to_string();
        let sample = if let Some(ctx) = item.context.as_deref() {
            format!("{} (target={}, context={})", reason, item.target, ctx)
        } else {
            format!("{} (target={})", reason, item.target)
        };
        by_reason.entry(reason).or_default().push(sample);
        *by_kind.entry(format!("{:?}", item.kind)).or_insert(0) += 1;
        if matches!(
            item.kind,
            CoverageGapKind::Route | CoverageGapKind::StopCondition
        ) {
            if let Some(tmpl) = template_hint(&item.target) {
                *by_template.entry(tmpl).or_insert(0) += 1;
            }
        }
    }

    out.push_str("## By Kind\n\n");
    for (kind, count) in by_kind {
        out.push_str(&format!("- {}: {}\n", kind, count));
    }
    out.push('\n');

    if !by_template.is_empty() {
        let mut template_rows: Vec<(String, usize)> = by_template.into_iter().collect();
        template_rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out.push_str("## Route Template Hotspots\n\n");
        for (tmpl, count) in template_rows.iter().take(20) {
            out.push_str(&format!("- `{tmpl}`: {count}\n"));
        }
        if template_rows.len() > 20 {
            out.push_str(&format!(
                "- ... ({} more templates)\n",
                template_rows.len().saturating_sub(20)
            ));
        }
        out.push('\n');
    }

    out.push_str("## Sample Items (top 5 per reason)\n\n");
    for (reason, samples) in by_reason {
        out.push_str(&format!("### `{reason}`\n\n"));
        for sample in samples.iter().take(5) {
            out.push_str(&format!("- {sample}\n"));
        }
        if samples.len() > 5 {
            out.push_str(&format!(
                "- ... ({} more)\n",
                samples.len().saturating_sub(5)
            ));
        }
        out.push('\n');
    }

    out.push_str("_Full raw items are available in coverage-gaps.json._\n");
    out
}
