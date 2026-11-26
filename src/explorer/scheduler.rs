use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet, VecDeque};

use url::Url;

use crate::config::ExplorationStrategy;
use crate::explorer::priority::{EnqueueSignals, NoveltyScorer};
use crate::output::checkpoint::QueuedUrl;
use crate::scope::ScopeFilter;

/// Wrapper for priority-heap ordering (lower score = higher priority; FIFO
/// tie-breaking via monotonic `seq`).
#[derive(Debug, Clone)]
struct ScoredUrl {
    score: i32,
    seq: u64,
    item: QueuedUrl,
}

impl PartialEq for ScoredUrl {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.seq == other.seq
    }
}
impl Eq for ScoredUrl {}

impl PartialOrd for ScoredUrl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredUrl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| self.seq.cmp(&other.seq))
    }
}

/// High priority for the first concrete URL matching an unvisited dynamic route
/// template (`/:id`, `/:slug`, ...): behind entry `/` (`0`), ahead of explicit
/// seeds (`5`), bulk static seeds (`10`), deprioritized routes (`40`), and
/// ordinary discovered links (`100`).
const DYNAMIC_TEMPLATE_BOOST_PRIORITY: i32 = 3;

#[derive(Debug, Clone)]
pub(super) struct ScanScheduler {
    queue: VecDeque<QueuedUrl>,
    priority_heap: BinaryHeap<Reverse<ScoredUrl>>,
    queued_urls: HashSet<String>,
    /// Parameterized route templates (`/:id`, `/:slug`, ...) that have already
    /// been visited or have already had one concrete URL boosted to high priority.
    seen_dynamic_templates: HashSet<String>,
    /// Optional source-discovered route templates (e.g. `/towns/:slug`).
    route_templates: crate::explorer::template_sampler::RouteTemplates,
    next_seq: u64,
    pub(super) scorer: NoveltyScorer,
}

impl ScanScheduler {
    pub(super) fn new(entry_url: String) -> Self {
        let mut scheduler = Self {
            queue: VecDeque::new(),
            priority_heap: BinaryHeap::new(),
            queued_urls: HashSet::new(),
            seen_dynamic_templates: HashSet::new(),
            route_templates: crate::explorer::template_sampler::RouteTemplates::default(),
            next_seq: 0,
            scorer: NoveltyScorer::new(),
        };
        let canonical = super::url_utils::canonicalize_crawl_url(&entry_url);
        if scheduler.queued_urls.insert(canonical.clone()) {
            scheduler.mark_visited_template(&canonical);
            scheduler.queue.push_back(QueuedUrl {
                url: canonical,
                depth: 0,
                priority: 0,
            });
        }
        scheduler
    }

    pub(super) fn from_checkpoint(queue: Vec<QueuedUrl>, queued_urls: Vec<String>) -> Self {
        let mut scheduler = Self {
            queue: VecDeque::new(),
            priority_heap: BinaryHeap::new(),
            queued_urls: HashSet::new(),
            seen_dynamic_templates: HashSet::new(),
            route_templates: crate::explorer::template_sampler::RouteTemplates::default(),
            next_seq: 0,
            scorer: NoveltyScorer::new(),
        };

        // Re-enqueue checkpoint entries through the canonicalization path so
        // noisy query variants collapse on resume.
        for mut item in queue {
            let canonical = super::url_utils::canonicalize_crawl_url(&item.url);
            if scheduler.queued_urls.insert(canonical.clone()) {
                item.url = canonical;
                scheduler.queue.push_back(item);
            } else {
                // Already queued: keep the highest priority (lowest value) and
                // shallowest depth.
                if let Some(existing) = scheduler.queue.iter_mut().find(|q| q.url == canonical) {
                    existing.priority = existing.priority.min(item.priority);
                    existing.depth = existing.depth.min(item.depth);
                }
            }
        }
        for url in queued_urls {
            scheduler
                .queued_urls
                .insert(super::url_utils::canonicalize_crawl_url(&url));
        }

        scheduler
    }

    pub(super) fn set_route_templates(
        &mut self,
        templates: crate::explorer::template_sampler::RouteTemplates,
    ) {
        self.route_templates = templates;
    }

    fn dynamic_template_for_url(&self, url: &str) -> Option<String> {
        if let Some(tmpl) = crate::explorer::template_sampler::url_to_template_path(url)
            && tmpl.contains("/:")
        {
            return Some(tmpl);
        }
        self.route_templates.template_for_url(url)
    }

    fn claim_dynamic_template_boost(&mut self, canonical: &str) -> bool {
        let Some(tmpl) = self.dynamic_template_for_url(canonical) else {
            return false;
        };
        self.seen_dynamic_templates.insert(tmpl)
    }

    /// Record that a concrete URL matching a dynamic route template has been
    /// visited so subsequent instances of the same template are not boosted.
    pub(super) fn mark_visited_template(&mut self, url: &str) {
        let canonical = super::url_utils::canonicalize_crawl_url(url);
        if let Some(tmpl) = self.dynamic_template_for_url(&canonical) {
            self.seen_dynamic_templates.insert(tmpl);
        }
    }

    pub(super) fn len(&self) -> usize {
        self.queue.len() + self.priority_heap.len()
    }

    pub(super) fn clear(&mut self) {
        self.queue.clear();
        self.priority_heap.clear();
        self.queued_urls.clear();
        self.seen_dynamic_templates.clear();
        self.next_seq = 0;
    }

    pub(super) fn queue_snapshot(&self) -> Vec<QueuedUrl> {
        let mut snapshot: Vec<QueuedUrl> = self.queue.iter().cloned().collect();
        for Reverse(scored) in &self.priority_heap {
            snapshot.push(scored.item.clone());
        }
        snapshot
    }

    pub(super) fn queued_urls_snapshot(&self) -> Vec<String> {
        self.queued_urls.iter().cloned().collect()
    }

    pub(super) fn enqueue(&mut self, url: String, depth: usize) {
        let canonical = super::url_utils::canonicalize_crawl_url(&url);
        if self.queued_urls.insert(canonical.clone()) {
            if self.claim_dynamic_template_boost(&canonical) {
                self.insert_by_priority_fifo(QueuedUrl {
                    url: canonical,
                    depth,
                    priority: DYNAMIC_TEMPLATE_BOOST_PRIORITY,
                });
            } else {
                self.queue.push_back(QueuedUrl {
                    url: canonical,
                    depth,
                    priority: 100,
                });
            }
        }
    }

    /// Put `url` back at the end of the queue even though it was queued
    /// before (one retry after a failed navigation).
    pub(super) fn requeue(&mut self, url: &str, depth: usize) {
        let canonical = super::url_utils::canonicalize_crawl_url(url);
        self.queued_urls.insert(canonical.clone());
        self.queue.push_back(QueuedUrl {
            url: canonical,
            depth,
            priority: 100,
        });
    }

    /// Put `url` back at the front of the queue (a visit that was cut off:
    /// it is explored first when the crawl continues). No duplicate when it
    /// is queued already.
    pub(super) fn requeue_front(&mut self, url: &str, depth: usize) {
        let canonical = super::url_utils::canonicalize_crawl_url(url);
        self.queued_urls.insert(canonical.clone());
        let queued = self.queue.iter().any(|q| q.url == canonical)
            || self
                .priority_heap
                .iter()
                .any(|Reverse(s)| s.item.url == canonical);
        if !queued {
            self.queue.push_front(QueuedUrl {
                url: canonical,
                depth,
                priority: 0,
            });
        }
    }

    /// Insert `item` at the end of its priority tier (lower `priority` values
    /// pop first; items with equal priority preserve FIFO insertion order).
    fn insert_by_priority_fifo(&mut self, item: QueuedUrl) {
        let idx = self
            .queue
            .iter()
            .position(|q| q.priority > item.priority)
            .unwrap_or(self.queue.len());
        self.queue.insert(idx, item);
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// Re-order initial seeds on a fresh scan so the entry URL (`/`) is always
    /// visited first (priority `0`), explicit `scan.seed_urls` follow in order
    /// (priority `5`), normal discovered/file seeds are visited breadth-first by
    /// path depth (priority `10`), and routes in `deprioritize_routes` follow in
    /// a lower tier (priority `40`), preserving FIFO order within each depth.
    pub(super) fn prioritize_initial_seeds(
        &mut self,
        entry_url: &str,
        explicit_seeds: &[String],
        deprioritize_routes: &[String],
        strategy: ExplorationStrategy,
        novelty_scoring: bool,
    ) {
        let entry_canonical = super::url_utils::canonicalize_crawl_url(entry_url);
        let explicit_pos: std::collections::HashMap<String, usize> = explicit_seeds
            .iter()
            .enumerate()
            .map(|(i, u)| (super::url_utils::canonicalize_crawl_url(u), i))
            .collect();
        let deprioritized: HashSet<String> = deprioritize_routes
            .iter()
            .map(|r| normalize_route_path_for_match(r))
            .collect();

        let mut items: Vec<(usize, QueuedUrl)> = Vec::with_capacity(self.len());
        let mut orig_idx = 0usize;
        while let Some(item) = self.queue.pop_front() {
            items.push((orig_idx, item));
            orig_idx += 1;
        }
        // Drain heap in priority order so tie-breaking preserves relative order.
        let mut heap_items = Vec::with_capacity(self.priority_heap.len());
        while let Some(Reverse(scored)) = self.priority_heap.pop() {
            heap_items.push(scored.item);
        }
        for item in heap_items {
            items.push((orig_idx, item));
            orig_idx += 1;
        }

        let mut ranked: Vec<((u8, usize, usize, usize), QueuedUrl)> = items
            .into_iter()
            .map(|(idx, mut item)| {
                let key = if item.url == entry_canonical {
                    item.priority = 0;
                    (0u8, 0usize, 0usize, idx)
                } else if let Some(&seed_idx) = explicit_pos.get(&item.url) {
                    item.priority = 5;
                    (1u8, 0usize, seed_idx, idx)
                } else if !deprioritized.is_empty() && {
                    let path = normalize_route_path_for_match(&item.url);
                    deprioritized.contains(&path)
                        || crate::explorer::template_sampler::url_to_template_path(&item.url)
                            .map(|t| normalize_route_path_for_match(&t))
                            .is_some_and(|t| deprioritized.contains(&t))
                } {
                    item.priority = 40;
                    (3u8, url_path_depth(&item.url), 0usize, idx)
                } else {
                    item.priority = 10;
                    (2u8, url_path_depth(&item.url), 0usize, idx)
                };
                (key, item)
            })
            .collect();

        ranked.sort_by_key(|(key, _)| *key);

        let use_heap = novelty_scoring && matches!(strategy, ExplorationStrategy::Priority);
        for ((tier, path_depth, _, _), mut item) in ranked {
            if use_heap {
                let depth_offset = i32::try_from(path_depth).unwrap_or(20).min(20);
                let score = match tier {
                    0 => 0,
                    1 => 5,
                    2 => 10_i32.saturating_add(depth_offset),
                    _ => 40_i32.saturating_add(depth_offset),
                };
                item.priority = score;
                let seq = self.alloc_seq();
                self.priority_heap
                    .push(Reverse(ScoredUrl { score, seq, item }));
            } else {
                self.queue.push_back(item);
            }
        }
    }

    /// Enqueue with explicit priority. Lower `priority` values pop earlier;
    /// items with the same priority stay in FIFO insertion order.
    pub(super) fn enqueue_priority(
        &mut self,
        url: String,
        depth: usize,
        priority: i32,
        base_url: &Url,
        scope_filter: Option<&ScopeFilter>,
        strategy: ExplorationStrategy,
        novelty_scoring: bool,
        from_new_dom_context: bool,
    ) {
        if novelty_scoring && matches!(strategy, ExplorationStrategy::Priority) {
            let signals = EnqueueSignals {
                route_template: crate::explorer::template_sampler::url_to_template_path(&url),
                from_nav: true,
                from_new_dom_context,
                depth,
            };
            self.enqueue_scored(url, depth, &signals, base_url, scope_filter);
            return;
        }

        if let Some(sf) = scope_filter {
            if let Ok(u) = Url::parse(&url) {
                if super::url_utils::same_origin(base_url, &u) && !sf.allows_path(u.as_str()) {
                    return;
                }
            }
        }
        let canonical = super::url_utils::canonicalize_crawl_url(&url);
        if self.queued_urls.insert(canonical.clone()) {
            let effective_priority = if self.claim_dynamic_template_boost(&canonical) {
                priority.min(DYNAMIC_TEMPLATE_BOOST_PRIORITY)
            } else {
                priority
            };
            let item = QueuedUrl {
                url: canonical,
                depth,
                priority: effective_priority,
            };
            self.insert_by_priority_fifo(item);
            return;
        }

        // Already queued: allow reprioritization (e.g. discovered in nav later)
        // while keeping FIFO order within each priority tier.
        if let Some(pos) = self.queue.iter().position(|q| q.url == canonical) {
            if let Some(mut existing) = self.queue.remove(pos) {
                let improved = priority < existing.priority;
                if improved {
                    existing.priority = priority;
                }
                if depth < existing.depth {
                    existing.depth = depth;
                }
                if improved {
                    self.insert_by_priority_fifo(existing);
                } else {
                    self.queue.insert(pos, existing);
                }
            }
        }
    }

    pub(super) fn enqueue_scoped(
        &mut self,
        url: String,
        depth: usize,
        base_url: &Url,
        scope_filter: Option<&ScopeFilter>,
        strategy: ExplorationStrategy,
        novelty_scoring: bool,
        from_new_dom_context: bool,
    ) {
        if novelty_scoring && matches!(strategy, ExplorationStrategy::Priority) {
            let signals = EnqueueSignals {
                route_template: crate::explorer::template_sampler::url_to_template_path(&url),
                from_nav: false,
                from_new_dom_context,
                depth,
            };
            self.enqueue_scored(url, depth, &signals, base_url, scope_filter);
            return;
        }

        if let Some(sf) = scope_filter {
            if let Ok(u) = Url::parse(&url) {
                if super::url_utils::same_origin(base_url, &u) && !sf.allows_path(u.as_str()) {
                    return;
                }
            }
        }
        self.enqueue(url, depth);
    }

    /// Enqueue a URL with novelty-based scoring. The scorer computes a
    /// priority score and the URL is placed in the priority heap.
    pub(super) fn enqueue_scored(
        &mut self,
        url: String,
        depth: usize,
        signals: &EnqueueSignals,
        base_url: &Url,
        scope_filter: Option<&ScopeFilter>,
    ) {
        if let Some(sf) = scope_filter {
            if let Ok(u) = Url::parse(&url) {
                if super::url_utils::same_origin(base_url, &u) && !sf.allows_path(u.as_str()) {
                    return;
                }
            }
        }
        let canonical = super::url_utils::canonicalize_crawl_url(&url);
        if self.queued_urls.insert(canonical.clone()) {
            let dynamic_tmpl = self.dynamic_template_for_url(&canonical);
            let boosted = dynamic_tmpl
                .as_ref()
                .is_some_and(|tmpl| self.seen_dynamic_templates.insert(tmpl.clone()));
            let score = if boosted {
                DYNAMIC_TEMPLATE_BOOST_PRIORITY
            } else {
                let mut s = self.scorer.score(signals);
                if dynamic_tmpl.is_some()
                    && signals
                        .route_template
                        .as_deref()
                        .is_some_and(|t| self.scorer.is_template_novel(t))
                {
                    s = s.saturating_add(40);
                }
                s
            };
            let seq = self.alloc_seq();
            self.priority_heap.push(Reverse(ScoredUrl {
                score,
                seq,
                item: QueuedUrl {
                    url: canonical,
                    depth,
                    priority: score,
                },
            }));
        }
    }

    /// The next item in exploration order. The crawl pops through
    /// [`Self::pop_next_matching`]; this is its reference order.
    #[cfg(test)]
    pub(super) fn pop_next(&mut self, strategy: ExplorationStrategy) -> Option<QueuedUrl> {
        match strategy {
            ExplorationStrategy::BreadthFirst => self.queue.pop_front(),
            ExplorationStrategy::DepthFirst => self.queue.pop_back(),
            ExplorationStrategy::Priority => {
                // Prefer the scored heap; fall back to the FIFO queue.
                if let Some(Reverse(scored)) = self.priority_heap.pop() {
                    Some(scored.item)
                } else {
                    self.queue.pop_front()
                }
            }
        }
    }

    /// The next item `eligible` accepts, in exploration order: breadth-first
    /// takes the queue front, depth-first the back, priority the scored heap
    /// first, then the queue front. Items passed over stay queued where they
    /// were; with every item eligible this is plain exploration order.
    pub(super) fn pop_next_matching(
        &mut self,
        strategy: ExplorationStrategy,
        mut eligible: impl FnMut(&QueuedUrl) -> bool,
    ) -> Option<QueuedUrl> {
        fn from_queue(
            queue: &mut VecDeque<QueuedUrl>,
            eligible: &mut dyn FnMut(&QueuedUrl) -> bool,
            back: bool,
        ) -> Option<QueuedUrl> {
            let pos = if back {
                queue.iter().rposition(eligible)
            } else {
                queue.iter().position(eligible)
            }?;
            queue.remove(pos)
        }
        match strategy {
            ExplorationStrategy::BreadthFirst => from_queue(&mut self.queue, &mut eligible, false),
            ExplorationStrategy::DepthFirst => from_queue(&mut self.queue, &mut eligible, true),
            ExplorationStrategy::Priority => {
                // Prefer the scored heap; fall back to the FIFO queue.
                let mut passed_over = Vec::new();
                let mut found = None;
                while let Some(Reverse(scored)) = self.priority_heap.pop() {
                    if eligible(&scored.item) {
                        found = Some(scored.item);
                        break;
                    }
                    passed_over.push(scored);
                }
                for scored in passed_over {
                    self.priority_heap.push(Reverse(scored));
                }
                found.or_else(|| from_queue(&mut self.queue, &mut eligible, false))
            }
        }
    }

    pub(super) fn record_visit_for_novelty(&mut self, url: &str, fingerprint: &str) {
        self.mark_visited_template(url);
        if let Some(template) = crate::explorer::template_sampler::url_to_template_path(url) {
            self.scorer.record_visit(&template, fingerprint);
        } else {
            self.scorer.record_visit(url, fingerprint);
        }
    }

    pub(super) fn purge_template_from_queue(&mut self, template: &str) -> usize {
        let mut removed = 0usize;
        let mut out = VecDeque::with_capacity(self.queue.len());
        while let Some(item) = self.queue.pop_front() {
            let matches_template =
                crate::explorer::template_sampler::url_to_template_path(&item.url)
                    .as_deref()
                    .is_some_and(|t| t == template);
            if matches_template {
                removed += 1;
                continue;
            }
            out.push_back(item);
        }
        self.queue = out;
        removed
    }
}

fn normalize_route_path_for_match(raw: &str) -> String {
    let raw = raw.trim();
    let path = if let Ok(url) = Url::parse(raw) {
        super::url_utils::effective_url_path_and_query(&url).0
    } else {
        let without_query = raw.split('?').next().unwrap_or(raw);
        match without_query.split_once('#') {
            Some((p, f)) if super::url_utils::fragment_is_route(Some(f)) => {
                let frag = f.split('?').next().unwrap_or(f).trim_end_matches('/');
                format!("{}/#{frag}", p.trim_end_matches('/'))
            }
            Some((p, _)) => p.to_string(),
            None => without_query.to_string(),
        }
    };
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Number of non-empty path segments in `url_str` (`/` = 0, `/clients` = 1,
/// `/staff/administration/warehouse-stations` = 3). Supports hash routes via
/// [`super::url_utils::effective_url_path_and_query`].
pub(super) fn url_path_depth(url_str: &str) -> usize {
    let Ok(url) = Url::parse(url_str) else {
        return usize::MAX;
    };
    let (path, _) = super::url_utils::effective_url_path_and_query(&url);
    path.split('/').filter(|seg| !seg.is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::ScanScheduler;
    use crate::output::checkpoint::QueuedUrl;

    #[test]
    fn pop_next_matching_skips_ineligible_items_and_keeps_them_queued() {
        use crate::config::ExplorationStrategy;
        for strategy in [
            ExplorationStrategy::BreadthFirst,
            ExplorationStrategy::DepthFirst,
            ExplorationStrategy::Priority,
        ] {
            let urls = ["https://x.test/a", "https://x.test/b", "https://x.test/c"];
            let base = url::Url::parse("https://x.test/").expect("url");
            let fill = || {
                let mut scheduler = ScanScheduler::new(urls[0].to_string());
                scheduler.enqueue(urls[1].to_string(), 1);
                // Scored into the priority heap under the priority strategy.
                scheduler.enqueue_scoped(
                    urls[2].to_string(),
                    1,
                    &base,
                    None,
                    strategy,
                    true,
                    false,
                );
                scheduler
            };
            // Every item eligible: the same order as pop_next.
            let (mut plain, mut matching) = (fill(), fill());
            while let Some(expected) = plain.pop_next(strategy) {
                let got = matching
                    .pop_next_matching(strategy, |_| true)
                    .expect("same length");
                assert_eq!(got.url, expected.url, "{strategy:?}");
            }
            assert!(matching.pop_next_matching(strategy, |_| true).is_none());

            // The next item is passed over, not lost, and keeps its place.
            let mut scheduler = fill();
            let first = fill().pop_next(strategy).expect("item").url;
            let got = scheduler
                .pop_next_matching(strategy, |q| q.url != first)
                .expect("an eligible item");
            assert_ne!(got.url, first);
            assert_eq!(scheduler.len(), 2);
            assert_eq!(scheduler.pop_next(strategy).expect("item").url, first);
            assert!(scheduler.pop_next_matching(strategy, |_| false).is_none());
            assert_eq!(scheduler.len(), 1);
        }
    }

    #[test]
    fn enqueue_collapses_non_semantic_query_variants() {
        let mut scheduler =
            ScanScheduler::new("https://app.example.com/dashboard?sort=name&dir=asc".to_string());
        scheduler.enqueue(
            "https://app.example.com/dashboard?sort=created_at&dir=desc&page=2".to_string(),
            1,
        );

        assert_eq!(scheduler.len(), 1);
        let queue = scheduler.queue_snapshot();
        assert_eq!(queue[0].url, "https://app.example.com/dashboard");
    }

    #[test]
    fn observed_ui_tabs_survive_queue_and_checkpoint_dedup() {
        for route in ["/account", "/#/account"] {
            let base = format!("https://app.example.com{route}");
            let mut scheduler = ScanScheduler::new(base.clone());
            scheduler.enqueue(format!("{base}?tab=payout"), 1);
            scheduler.enqueue(format!("{base}?tab=payments"), 1);
            scheduler.enqueue(format!("{base}?utm_source=mail&tab=payout&page=2"), 1);
            assert_eq!(scheduler.len(), 3);
            let restored = ScanScheduler::from_checkpoint(
                scheduler.queue_snapshot(),
                scheduler.queued_urls_snapshot(),
            );
            assert_eq!(restored.len(), 3);
            assert!(
                restored
                    .queue_snapshot()
                    .iter()
                    .any(|q| q.url == format!("{base}?tab=payout"))
            );
        }
    }

    #[test]
    fn from_checkpoint_canonicalizes_and_dedupes_queue() {
        let scheduler = ScanScheduler::from_checkpoint(
            vec![
                QueuedUrl {
                    url: "https://app.example.com/dashboard?sort=name".to_string(),
                    depth: 1,
                    priority: 100,
                },
                QueuedUrl {
                    url: "https://app.example.com/dashboard?sort=updated_at&dir=asc".to_string(),
                    depth: 1,
                    priority: 100,
                },
            ],
            vec![],
        );

        assert_eq!(scheduler.len(), 1);
        let queue = scheduler.queue_snapshot();
        assert_eq!(queue[0].url, "https://app.example.com/dashboard");
    }

    #[test]
    fn enqueue_priority_preserves_fifo_within_tiers_and_entry_pops_first() {
        use crate::config::ExplorationStrategy;
        let base = url::Url::parse("https://app.example.com/").expect("url");
        let mut scheduler = ScanScheduler::new("https://app.example.com/".to_string());

        // Enqueueing sorted seeds at priority 0 must preserve FIFO order so `/`
        // pops first, not dead last (regression against LIFO `push_front`).
        for seed in [
            "https://app.example.com/",
            "https://app.example.com/about",
            "https://app.example.com/clients",
            "https://app.example.com/verify",
        ] {
            scheduler.enqueue_priority(
                seed.to_string(),
                0,
                0,
                &base,
                None,
                ExplorationStrategy::BreadthFirst,
                false,
                false,
            );
        }

        let mut popped = Vec::new();
        while let Some(item) = scheduler.pop_next(ExplorationStrategy::BreadthFirst) {
            popped.push(item.url);
        }
        assert_eq!(
            popped,
            vec![
                "https://app.example.com/",
                "https://app.example.com/about",
                "https://app.example.com/clients",
                "https://app.example.com/verify",
            ]
        );

        // Mixed priority tiers: higher priority (lower value) jumps ahead of
        // lower priority while keeping FIFO order inside each tier.
        let mut tiered = ScanScheduler::new("https://app.example.com/".to_string());
        for (path, pri) in [
            ("/p10-a", 10),
            ("/p5-a", 5),
            ("/p10-b", 10),
            ("/p0-a", 0),
            ("/p5-b", 5),
            ("/p0-b", 0),
        ] {
            tiered.enqueue_priority(
                format!("https://app.example.com{path}"),
                0,
                pri,
                &base,
                None,
                ExplorationStrategy::BreadthFirst,
                false,
                false,
            );
        }
        let mut order = Vec::new();
        while let Some(item) = tiered.pop_next(ExplorationStrategy::BreadthFirst) {
            order.push(item.url);
        }
        assert_eq!(
            order,
            vec![
                "https://app.example.com/",
                "https://app.example.com/p0-a",
                "https://app.example.com/p0-b",
                "https://app.example.com/p5-a",
                "https://app.example.com/p5-b",
                "https://app.example.com/p10-a",
                "https://app.example.com/p10-b",
            ]
        );
    }

    #[test]
    fn prioritize_initial_seeds_orders_entry_explicit_then_breadth_first_depth() {
        use crate::config::ExplorationStrategy;
        let base = url::Url::parse("https://app.example.com/").expect("url");
        for (strategy, novelty) in [
            (ExplorationStrategy::BreadthFirst, false),
            (ExplorationStrategy::Priority, true),
        ] {
            let mut scheduler = ScanScheduler::new("https://app.example.com/".to_string());
            let explicit = vec!["https://app.example.com/custom/special".to_string()];
            for seed in [
                "https://app.example.com/custom/special",
                "https://app.example.com/staff/administration/warehouse-stations",
                "https://app.example.com/admin/billing",
                "https://app.example.com/clients",
                "https://app.example.com/orders",
                "https://app.example.com/settings",
                "https://app.example.com/",
            ] {
                scheduler.enqueue_priority(
                    seed.to_string(),
                    0,
                    0,
                    &base,
                    None,
                    strategy,
                    novelty,
                    false,
                );
            }
            scheduler.prioritize_initial_seeds(base.as_str(), &explicit, &[], strategy, novelty);

            let mut popped = Vec::new();
            while let Some(item) = scheduler.pop_next(strategy) {
                popped.push((item.url, item.priority));
            }
            let urls: Vec<&str> = popped.iter().map(|(u, _)| u.as_str()).collect();
            assert_eq!(
                urls,
                vec![
                    "https://app.example.com/",
                    "https://app.example.com/custom/special",
                    "https://app.example.com/clients",
                    "https://app.example.com/orders",
                    "https://app.example.com/settings",
                    "https://app.example.com/admin/billing",
                    "https://app.example.com/staff/administration/warehouse-stations",
                ],
                "strategy={strategy:?} novelty={novelty}"
            );
            assert_eq!(popped[0].1, 0);
            assert_eq!(popped[1].1, 5);
        }
    }

    #[test]
    fn dynamic_template_first_concrete_url_boosted_ahead_of_static_routes_both_modes() {
        use crate::config::ExplorationStrategy;
        let base = url::Url::parse("http://localhost:3000/").expect("url");
        for (strategy, novelty) in [
            (ExplorationStrategy::BreadthFirst, false),
            (ExplorationStrategy::Priority, true),
        ] {
            let mut scheduler = ScanScheduler::new(base.to_string());
            scheduler.set_route_templates(crate::explorer::template_sampler::RouteTemplates::new(
                &["/towns/:slug"],
            ));
            for seed in [
                "http://localhost:3000/about",
                "http://localhost:3000/pricing",
                "http://localhost:3000/contact",
            ] {
                scheduler.enqueue_priority(
                    seed.to_string(),
                    0,
                    10,
                    &base,
                    None,
                    strategy,
                    novelty,
                    false,
                );
            }
            scheduler.prioritize_initial_seeds(base.as_str(), &[], &[], strategy, novelty);
            assert_eq!(
                scheduler.pop_next(strategy).expect("entry").url,
                "http://localhost:3000/"
            );

            // List page discovers two concrete instances of `/customers/:id` and
            // two concrete instances of `/towns/:slug`.
            for link in [
                "http://localhost:3000/customers/42",
                "http://localhost:3000/customers/99",
                "http://localhost:3000/towns/brinkley-ar",
                "http://localhost:3000/towns/little-rock",
            ] {
                scheduler.enqueue_scoped(
                    link.to_string(),
                    1,
                    &base,
                    None,
                    strategy,
                    novelty,
                    false,
                );
            }

            let mut popped = Vec::new();
            while let Some(item) = scheduler.pop_next(strategy) {
                popped.push((item.url, item.priority));
            }
            let urls: Vec<&str> = popped.iter().map(|(u, _)| u.as_str()).collect();
            assert_eq!(
                urls,
                vec![
                    "http://localhost:3000/customers/42",
                    "http://localhost:3000/towns/brinkley-ar",
                    "http://localhost:3000/about",
                    "http://localhost:3000/pricing",
                    "http://localhost:3000/contact",
                    "http://localhost:3000/customers/99",
                    "http://localhost:3000/towns/little-rock",
                ],
                "strategy={strategy:?} novelty={novelty}"
            );
            assert_eq!(popped[0].1, 3);
            assert_eq!(popped[1].1, 3);
            assert!(popped[5].1 > popped[4].1);
            assert!(popped[6].1 > popped[4].1);
        }
    }

    #[test]
    fn visited_dynamic_template_is_not_boosted_again() {
        use crate::config::ExplorationStrategy;
        let base = url::Url::parse("http://localhost:3000/").expect("url");
        for (strategy, novelty) in [
            (ExplorationStrategy::BreadthFirst, false),
            (ExplorationStrategy::Priority, true),
        ] {
            let mut scheduler = ScanScheduler::new(base.to_string());
            for seed in [
                "http://localhost:3000/about",
                "http://localhost:3000/pricing",
                "http://localhost:3000/contact",
            ] {
                scheduler.enqueue_priority(
                    seed.to_string(),
                    0,
                    10,
                    &base,
                    None,
                    strategy,
                    novelty,
                    false,
                );
            }
            scheduler.prioritize_initial_seeds(base.as_str(), &[], &[], strategy, novelty);
            let _ = scheduler.pop_next(strategy);

            scheduler.mark_visited_template("http://localhost:3000/invoices/1");
            scheduler.enqueue_scoped(
                "http://localhost:3000/invoices/2".to_string(),
                1,
                &base,
                None,
                strategy,
                novelty,
                false,
            );

            let mut urls = Vec::new();
            while let Some(item) = scheduler.pop_next(strategy) {
                urls.push(item.url);
            }
            assert_eq!(
                urls,
                vec![
                    "http://localhost:3000/about",
                    "http://localhost:3000/pricing",
                    "http://localhost:3000/contact",
                    "http://localhost:3000/invoices/2",
                ],
                "strategy={strategy:?} novelty={novelty}"
            );
        }
    }

    #[test]
    fn prioritize_initial_seeds_deprioritizes_public_routes_behind_app_routes() {
        use crate::config::ExplorationStrategy;
        let base = url::Url::parse("https://app.example.com/").expect("url");
        let explicit = vec!["https://app.example.com/ops".to_string()];
        let deprioritize = vec![
            "/about/".to_string(),
            "/pricing".to_string(),
            "https://app.example.com/privacy".to_string(),
            "/terms".to_string(),
            // Entry `/` and explicit seed `/ops` must remain at tiers 0 and 1.
            "/".to_string(),
            "/ops".to_string(),
        ];

        for (strategy, novelty) in [
            (ExplorationStrategy::BreadthFirst, false),
            (ExplorationStrategy::Priority, true),
        ] {
            let mut scheduler = ScanScheduler::new(base.to_string());
            for seed in [
                "https://app.example.com/about",
                "https://app.example.com/pricing",
                "https://app.example.com/privacy",
                "https://app.example.com/terms",
                "https://app.example.com/ops",
                "https://app.example.com/customers",
                "https://app.example.com/admin/billing",
                "https://app.example.com/",
            ] {
                scheduler.enqueue_priority(
                    seed.to_string(),
                    0,
                    0,
                    &base,
                    None,
                    strategy,
                    novelty,
                    false,
                );
            }
            scheduler.prioritize_initial_seeds(
                base.as_str(),
                &explicit,
                &deprioritize,
                strategy,
                novelty,
            );

            let mut popped = Vec::new();
            while let Some(item) = scheduler.pop_next(strategy) {
                popped.push((item.url, item.priority));
            }
            let urls: Vec<&str> = popped.iter().map(|(u, _)| u.as_str()).collect();
            assert_eq!(
                urls,
                vec![
                    "https://app.example.com/",
                    "https://app.example.com/ops",
                    "https://app.example.com/customers",
                    "https://app.example.com/admin/billing",
                    "https://app.example.com/about",
                    "https://app.example.com/pricing",
                    "https://app.example.com/privacy",
                    "https://app.example.com/terms",
                ],
                "strategy={strategy:?} novelty={novelty}"
            );
            assert_eq!(popped[0].1, 0);
            assert_eq!(popped[1].1, 5);
            assert!(popped[2].1 < 40 && popped[3].1 < 40);
            assert!(popped[4].1 >= 40 && popped[7].1 >= 40);
        }
    }
}
