use serde::{Deserialize, Serialize};

use crate::types::dom::LocatorStrategy;

// ---------------------------------------------------------------------------
// Top-level component classification
// ---------------------------------------------------------------------------

/// High-level classification of a detected UI component region.
/// Each variant carries structural metadata an LLM needs to understand what the
/// component does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ComponentType {
    Navigation {
        nav_type: NavType,
        items: Vec<NavItem>,
    },
    DataTable {
        columns: Vec<ColumnDef>,
        row_count: usize,
        has_pagination: bool,
        has_sorting: bool,
        has_filtering: bool,
        has_bulk_actions: bool,
    },
    Form {
        fields: Vec<FormFieldDef>,
        has_submit: bool,
        submit_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        submit_selector: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        submit_locators: Vec<LocatorStrategy>,
        /// Populated post-interaction when we correlate to the API call.
        submit_endpoint: Option<String>,
    },
    DetailView {
        entity_type: Option<String>,
        fields: Vec<DetailFieldDef>,
    },
    Dashboard {
        widgets: Vec<DashboardWidget>,
    },
    SearchInterface {
        input_selector: Option<String>,
        has_results_container: bool,
        has_filters: bool,
        filters: Vec<FilterDef>,
    },
    ListView {
        item_count: usize,
        /// CSS selector of one representative item
        item_selector: Option<String>,
        has_pagination: bool,
    },
    Modal {
        title: Option<String>,
        has_close_button: bool,
        inner_component: Option<Box<ComponentType>>,
    },
    TabGroup {
        tabs: Vec<TabDef>,
        active_index: Option<usize>,
    },
    Breadcrumbs {
        items: Vec<BreadcrumbItem>,
    },
    Chart {
        chart_type: String,
        canvas_or_svg: String,
    },
    StatsCard {
        label: Option<String>,
        value: Option<String>,
    },
    Calendar,
    FileUploadZone,
    RichTextEditor,
    ErrorPage {
        error_type: Option<String>,
        message: Option<String>,
    },
    EmptyState {
        message: Option<String>,
        has_cta: bool,
    },
    /// Catch-all for regions we can partially describe but don't match a known
    /// pattern confidently.
    Unknown {
        tag: String,
        role: Option<String>,
        child_count: usize,
    },
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavType {
    TopBar,
    Sidebar,
    TabBar,
    Breadcrumbs,
    Pagination,
    StepWizard,
    Footer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavItem {
    pub label: String,
    pub href: Option<String>,
    pub is_active: bool,
    pub icon: Option<String>,
}

// ---------------------------------------------------------------------------
// Data Table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDef {
    pub label: String,
    /// Inferred field name from header text (snake_cased)
    pub field: Option<String>,
    pub sortable: bool,
    /// Column index (0-based)
    pub index: usize,
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFieldDef {
    pub label: Option<String>,
    pub name: Option<String>,
    pub field_type: FormFieldType,
    pub required: bool,
    pub placeholder: Option<String>,
    pub selector: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<LocatorStrategy>,
    /// If interacting with this control changes the browser URL query string,
    /// record which query params it drives (useful for filter/search bars).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drives_query_params: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormFieldType {
    Text,
    Email,
    Password,
    Number,
    Tel,
    Url,
    Date,
    DateTime,
    Time,
    Color,
    File,
    Hidden,
    Textarea,
    Select {
        options: Vec<String>,
    },
    MultiSelect {
        options: Vec<String>,
    },
    Checkbox,
    Radio {
        group: Option<String>,
        options: Vec<String>,
    },
    Toggle,
    RichText,
    Unknown {
        raw_type: String,
    },
}

// ---------------------------------------------------------------------------
// Detail View
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailFieldDef {
    pub label: String,
    pub value_preview: Option<String>,
    /// Best guess: "text", "date", "email", "phone", "url", "badge", "image"
    pub value_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub widget_type: DashboardWidgetType,
    pub title: Option<String>,
    pub selector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardWidgetType {
    StatCard,
    Chart,
    Table,
    List,
    Calendar,
    RecentActivity,
    Unknown,
}

// ---------------------------------------------------------------------------
// Search / Filters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterDef {
    pub label: Option<String>,
    pub field: Option<String>,
    pub filter_type: FilterType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterType {
    Text,
    Select { options: Vec<String> },
    MultiSelect { options: Vec<String> },
    DateRange,
    NumberRange,
    Toggle,
    Unknown,
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabDef {
    pub label: String,
    pub is_active: bool,
    pub selector: String,
}

// ---------------------------------------------------------------------------
// Breadcrumbs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreadcrumbItem {
    pub label: String,
    pub href: Option<String>,
    pub is_current: bool,
}

// ---------------------------------------------------------------------------
// Classified View (final per-view output)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedView {
    /// Primary classification (the dominant pattern on the page)
    pub primary_type: String,
    /// Human-readable description auto-generated from classification
    pub description: String,
    /// All detected component regions
    pub components: Vec<DetectedComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomClassSample {
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub class_list: Vec<String>,
    #[serde(default)]
    pub has_inline_style: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomTextSample {
    pub text: String,
    pub selector: String,
    pub x_px: f64,
    pub y_px: f64,
    pub width_px: f64,
    pub height_px: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_x_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_y_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_width_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_height_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub class_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComponentVisualProfile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub class_list: Vec<String>,
    #[serde(default)]
    pub has_inline_style: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_style_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub z_index: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub border_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub border_radius_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub border_width_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding_x_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding_y_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margin_x_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margin_y_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_size_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_height_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_weight: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_padding_x_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_padding_y_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_font_size_px: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_border_radius_px: Option<f64>,

    // Extra DOM visibility/context for UI consistency diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe_class_list: Vec<String>,
    #[serde(default)]
    pub probe_has_inline_style: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_inline_style_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub class_samples: Vec<DomClassSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub text_samples: Vec<DomTextSample>,

    /// Best-effort design-token adherence mismatches (computed styles vs CSS variables on :root).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedComponent {
    /// Root CSS selector of this component region
    pub selector: String,
    /// Classification result
    pub component: ComponentType,
    /// Confidence 0.0–1.0
    pub confidence: f64,
    /// Optional computed style summary for consistency analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visual: Option<ComponentVisualProfile>,
}
