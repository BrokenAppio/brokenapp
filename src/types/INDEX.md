# Types Reference

## When to Read

Understanding data structures that flow between modules. These types are the API contract.

## api.rs — API Surface Types

| Type | Description |
|------|-------------|
| `HttpMethod` | Enum: Get, Post, Put, Patch, Delete, Head, Options (serde uppercase) |
| `EndpointKey` | `{ method: HttpMethod, path: String }` — identifies an API route |
| `ApiEndpoint` | Full endpoint with parameters, body schema, response |
| `TrafficEntry` | Single request/response pair with timing |
| `InteractionRef` | `{ view: ViewId, selector: String }` — DOM element that triggered API call |

## bugs.rs — Finding Types

| Type | Description |
|------|-------------|
| `Bug` | Core finding: id, severity, confidence, category, title, description, location, evidence |
| `BugSeverity` | Critical > High > Medium > Low > Info |
| `BugCategory` | BrokenLink, DeadButton, ServerError, ConsoleError, CorsError, AccessibilityViolation, ... |
| `BugLocation` | `{ url, view_id, selector, endpoint }` |
| `BugEvidence` | `{ screenshot, action_ids, network_log, console_log, dom_snapshot }` |
| `confidence` | `Option<f64>` — 0.0 to 1.0 reliability score |

## dom.rs — DOM Interaction Types

| Type | Description |
|------|-------------|
| `InteractiveElement` | `{ selector, label, element_type, interaction_result, found_on }` |
| `ElementType` | NavigationLink, Button, TextInput, SelectDropdown, Checkbox, RadioButton, ... |
| `InteractionResult` | Navigation, ModalOpen, ApiCall, DomMutation, NoEffect, Error |
| `InteractionSnapshot` | `{ appeared_elements, appeared_text, attribute_changes, modal_opened }` |
| `BoundingBox` | `{ x, y, width, height }` — element position |

## graph.rs — Graph Types

| Type | Description |
|------|-------------|
| `ViewId` | String alias — identifies a unique app view |
| `DomFingerprint` | Newtype for hashed DOM structure |
| `AppView` | Full view: id, url, fingerprint, title, components, elements, on_load_api_calls |
| `ViewTransition` | `{ from_view, to_view, trigger, url }` — state machine edge |
| `PerformanceMetrics` | Core Web Vitals for a view |

## classifier.rs — View Classification

| Type | Description |
|------|-------------|
| `ComponentType` | Enum (tagged, snake_case): Navigation, DataTable, Form, Card, List, ... |
| `FormFieldDef` | `{ label, name, field_type, required, selector }` |
| `DetectedComponent` | Instance of a ComponentType with location metadata |
| `ClassifiedView` | View with component analysis results |
