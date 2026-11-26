use serde::{Deserialize, Serialize};

use crate::types::api::EndpointKey;
use crate::types::graph::ViewId;

fn is_false(v: &bool) -> bool {
    !*v
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_dom_path_enter_none(v: &DomPathEnter) -> bool {
    matches!(v, DomPathEnter::None)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveElement {
    pub selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub element_type: ElementType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_result: Option<InteractionResult>,
    pub found_on: ViewId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounding_box: Option<BoundingBox>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<InteractionSnapshot>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_required_fields_in_form: u32,
    /// Alternative locator strategies with stability scores.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<LocatorStrategy>,
    /// Raw source-location evidence captured in the browser during discovery
    /// (React dev `_debugStack` frames, handler props, Astro dev annotations).
    /// Resolved to repo `file:line` after the scan by `code_link::runtime_source`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ElementSourceCapture>,
}

/// Browser-side source evidence for one element, captured during discovery.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ElementSourceCapture {
    /// Stack frames for the element's creation site and its owner chain,
    /// innermost first. URLs are as served by the dev server (unresolved).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<SourceFrame>,
    /// Event-handler prop names found on the element (e.g. `onClick`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handlers: Vec<String>,
    /// Already-resolved `file:line[:col]` from a framework dev annotation
    /// (e.g. Astro `data-astro-source-file` + `data-astro-source-loc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotated: Option<String>,
}

/// One unresolved stack frame captured in the browser.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SourceFrame {
    /// `render` (host element creation), `owner` (component up the chain),
    /// or `handler` (event handler function location).
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    pub url: String,
    pub line: u32,
    #[serde(default)]
    pub col: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ElementType {
    NavigationLink {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        href: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        in_nav: bool,
    },
    Button {
        #[serde(default)]
        form_submit: bool,
    },
    TextInput {
        input_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default)]
        required: bool,
    },
    SelectDropdown {
        #[serde(default)]
        options: Vec<SelectOption>,
    },
    Checkbox {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default)]
        checked: bool,
    },
    RadioButton {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
    },
    FileUpload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accept: Option<String>,
    },
    DatePicker,
    Toggle,
    Tab,
    ModalTrigger,
    DropdownMenu {
        #[serde(default, skip_serializing_if = "is_false")]
        in_nav: bool,
    },
    Accordion,
    SearchBar,
    Pagination,
    SortControl,
    FilterControl,
    DragHandle,
    ContextMenu,
    Other {
        tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectOption {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InteractionResult {
    Navigation {
        target_view: ViewId,
    },
    ModalOpen {
        modal_id: String,
    },
    ApiCall {
        endpoint: EndpointKey,
    },
    DomMutation {
        description: String,
    },
    FileDownload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
    },
    NoEffect,
    Error {
        message: String,
    },
    Multiple {
        interactions: Vec<InteractionResult>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InteractionRef {
    pub view: ViewId,
    pub selector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomPathLocator {
    pub segments: Vec<DomPathSegment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomPathSegment {
    pub selector: String,
    #[serde(default, skip_serializing_if = "is_dom_path_enter_none")]
    pub enter: DomPathEnter,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomPathEnter {
    None,
    Shadow,
    Frame,
}

impl Default for DomPathEnter {
    fn default() -> Self {
        Self::None
    }
}

// ---------------------------------------------------------------------------
// Post-interaction DOM snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InteractionSnapshot {
    /// New elements that appeared after the interaction
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub appeared_elements: Vec<AppearedElement>,
    /// Text content that appeared (validation errors, toast messages, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub appeared_text: Vec<AppearedText>,
    /// Attribute changes observed after the interaction (aria-expanded, class, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attribute_changes: Vec<AttributeChange>,
    /// Whether a modal/dialog was opened
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modal_opened: Option<ModalSnapshot>,
    /// Browser-level side effects that may not change the DOM, such as
    /// clipboard writes, storage clears, or imperative navigation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<InteractionSideEffect>,
    /// Whether capture was truncated due to large DOM changes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl InteractionSnapshot {
    pub fn is_empty(&self) -> bool {
        !self.truncated
            && self.appeared_elements.is_empty()
            && self.appeared_text.is_empty()
            && self.attribute_changes.is_empty()
            && self.modal_opened.is_none()
            && self.side_effects.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionSideEffect {
    /// Stable snake_case effect kind, e.g. clipboard_write or local_storage_clear.
    pub kind: String,
    /// Number of observed effect attempts during this interaction.
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppearedElement {
    pub selector: String,
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// "form_field", "button", "text", "container"
    pub element_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppearedText {
    pub selector: String,
    pub text: String,
    /// "error", "success", "info", "unknown"
    pub kind: String,
    /// True when the appeared text is inside a toast, alert, snackbar, or banner region.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_toast: bool,
    /// True when the text appeared inline inside a `<form>` (field validation).
    #[serde(default, skip_serializing_if = "is_false")]
    pub in_form: bool,
    /// True when the appeared toast/banner exposes an error action like "Copy error".
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_error_action: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeChange {
    pub selector: String,
    pub attribute: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModalSnapshot {
    pub selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub form_fields: Vec<crate::types::classifier::FormFieldDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buttons: Vec<String>,
}

/// A locator strategy for finding an element, with stability scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocatorStrategy {
    pub kind: LocatorKind,
    pub value: String,
    pub stability: f64,
    #[serde(default)]
    pub unique: bool,
}

/// Types of element locator strategies, ordered by stability.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocatorKind {
    TestId,
    Id,
    Aria,
    Name,
    Role,
    Class,
    DomPath,
    Structural,
}

impl LocatorKind {
    /// Default stability score for this locator kind.
    pub fn default_stability(&self) -> f64 {
        match self {
            Self::TestId => 0.95,
            Self::Id => 0.85,
            Self::Aria => 0.80,
            Self::Name => 0.75,
            Self::Role => 0.80,
            Self::Class => 0.60,
            Self::DomPath => 0.72,
            Self::Structural => 0.30,
        }
    }
}
