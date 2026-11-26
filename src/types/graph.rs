use serde::{Deserialize, Serialize};

use crate::types::api::EndpointKey;
use crate::types::classifier::{ComponentType, DetectedComponent};
use crate::types::dom::{InteractionRef, InteractiveElement, LocatorStrategy};

pub type ViewId = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct DomFingerprint(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppView {
    pub id: ViewId,
    pub url: String,
    pub fingerprint: DomFingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default = "default_component_type")]
    pub component_type: String,
    #[serde(default = "default_view_description")]
    pub description: String,
    #[serde(default)]
    pub components: Vec<ComponentType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_instances: Vec<DetectedComponent>,
    #[serde(default)]
    pub elements: Vec<InteractiveElement>,
    #[serde(default)]
    pub on_load_api_calls: Vec<EndpointKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,

    /// Parent view ID for sub-views (modals, tabs, etc.). None for top-level views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_view: Option<ViewId>,

    /// Interaction depth at which this view was discovered. 0 for top-level views.
    #[serde(default)]
    pub depth: usize,

    /// The selector that triggered this sub-view (e.g., the button that opened the modal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_selector: Option<String>,

    /// How this sub-view was reached from its parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_view_transition_type: Option<TransitionType>,
}

fn default_component_type() -> String {
    "unknown".to_string()
}

fn default_view_description() -> String {
    "Unclassified view".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewTransition {
    pub from_view: ViewId,
    pub to_view: ViewId,
    pub trigger: InteractionRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trigger_locators: Vec<LocatorStrategy>,
    pub transition_type: TransitionType,
    #[serde(default)]
    pub api_calls: Vec<EndpointKey>,
    #[serde(default)]
    pub preconditions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionType {
    Navigation,
    SpaRouteChange,
    ModalOpen,
    ModalClose,
    TabSwitch,
    AccordionToggle,
    ViewStateChange,
}
