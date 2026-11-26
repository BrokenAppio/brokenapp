use std::collections::{HashMap, HashSet};

/// Signals about a URL being enqueued, used to compute priority score.
#[derive(Debug, Clone, Default)]
pub struct EnqueueSignals {
    pub route_template: Option<String>,
    pub from_nav: bool,
    pub from_new_dom_context: bool,
    pub depth: usize,
}

/// Scores URLs for priority-based exploration. Lower score = higher priority.
#[derive(Debug, Clone)]
pub struct NoveltyScorer {
    seen_templates: HashSet<String>,
    seen_fingerprints: HashSet<String>,
    template_visit_counts: HashMap<String, usize>,
}

impl NoveltyScorer {
    pub fn new() -> Self {
        Self {
            seen_templates: HashSet::new(),
            seen_fingerprints: HashSet::new(),
            template_visit_counts: HashMap::new(),
        }
    }

    /// Compute priority score. Lower = higher priority.
    pub fn score(&self, signals: &EnqueueSignals) -> i32 {
        let mut score: i32 = 50; // baseline

        // New route template: highest priority
        if let Some(ref tmpl) = signals.route_template {
            if !self.seen_templates.contains(tmpl) {
                score -= 40;
            }
        }

        // Nav-discovered links get priority boost
        if signals.from_nav {
            score -= 10;
        }

        // From a new DOM context (unseen fingerprint)
        if signals.from_new_dom_context {
            score -= 10;
        }

        // Depth penalty: +2 per level, max +20
        score += (signals.depth as i32 * 2).min(20);

        // Template saturation: +5 per prior visit, max +40
        if let Some(ref tmpl) = signals.route_template {
            let visits = self.template_visit_counts.get(tmpl).copied().unwrap_or(0);
            score += (visits as i32 * 5).min(40);
        }

        score
    }

    /// Record that a view was visited (call after processing a view).
    pub fn record_visit(&mut self, route_template: &str, fingerprint: &str) {
        self.seen_templates.insert(route_template.to_string());
        self.seen_fingerprints.insert(fingerprint.to_string());
        *self
            .template_visit_counts
            .entry(route_template.to_string())
            .or_default() += 1;
    }

    /// Check if a fingerprint has been seen before.
    pub fn is_fingerprint_novel(&self, fingerprint: &str) -> bool {
        !self.seen_fingerprints.contains(fingerprint)
    }

    /// Check if a template has been seen before.
    pub fn is_template_novel(&self, template: &str) -> bool {
        !self.seen_templates.contains(template)
    }
}

impl Default for NoveltyScorer {
    fn default() -> Self {
        Self::new()
    }
}
