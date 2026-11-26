# DOM Module — Discovery & Interaction

## When to Read

Modifying element discovery, interaction behavior, or snapshot capture.

## Pipeline

```
1. discovery.rs — Find interactive elements on page (buttons, inputs, links)
2. classifier.rs — Classify elements and views into component types
3. heuristics.rs — Label analysis (submit, destructive, bad labels)
4. interaction.rs — Click/type/select with observation
5. snapshot.rs — MutationObserver capture (before/after DOM diff)
6. interaction_signals.rs — Pre-click pattern detection + classification
7. selector.rs — Stable selector generation
8. fingerprint.rs — DOM fingerprinting for view dedup
```

## Files

| File | Purpose |
|------|---------|
| `discovery.rs` | `discover_interactive_elements()` — main element finder |
| `classifier.rs` | View and component classification |
| `classify_js.rs` | JavaScript-based classification helpers (private) |
| `heuristics.rs` | Label analysis, destructive action detection |
| `interaction.rs` | Click/type/select with `InteractionObservation` |
| `interaction_signals.rs` | Pre-click patterns + post-interaction classification |
| `snapshot.rs` | MutationObserver DOM diff capture |
| `selector.rs` | Generate stable CSS selectors |
| `fingerprint.rs` | DOM fingerprinting for view deduplication |
| `mod.rs` | Module entry, exports `discover_interactive_elements()`, `fingerprint_dom()` |

## Key Types (from types/dom.rs)

| Type | Description |
|------|-------------|
| `InteractiveElement` | `{ selector, label, element_type, interaction_result, found_on }` |
| `ElementType` | NavigationLink, Button, TextInput, SelectDropdown, Checkbox, ... |
| `InteractionResult` | Navigation, ModalOpen, ApiCall, DomMutation, NoEffect, Error |
| `InteractionSnapshot` | `{ appeared_elements, appeared_text, attribute_changes, modal_opened }` |

## Key Types (from interaction_signals.rs)

| Type | Description |
|------|-------------|
| `PreClickPattern` | Accordion, Tab, DisclosureToggle, Modal, Dropdown, CopyToClipboard, Unknown |
| `InteractionClassification` | Dead, WeakResponse, ClientSideFunctional, NeedsVerification |
