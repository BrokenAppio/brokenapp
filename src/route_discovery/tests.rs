//! Fixture-tree tests for every route discovery adapter.

use super::*;

fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (rel, body) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, body).expect("write fixture");
    }
    dir
}

fn discover(dir: &tempfile::TempDir) -> RouteDiscovery {
    discover_routes(dir.path()).expect("discover")
}

fn route<'a>(d: &'a RouteDiscovery, path: &str, kind: &str) -> &'a DiscoveredRoute {
    d.routes
        .iter()
        .find(|r| r.path == path && r.kind == kind)
        .unwrap_or_else(|| panic!("missing {kind} {path}; have {:#?}", summary(d)))
}

fn summary(d: &RouteDiscovery) -> Vec<String> {
    d.routes
        .iter()
        .map(|r| format!("{} {} {}", r.kind, r.path, r.file))
        .collect()
}

fn page_paths(d: &RouteDiscovery) -> Vec<&str> {
    d.routes
        .iter()
        .filter(|r| r.kind == "page")
        .map(|r| r.path.as_str())
        .collect()
}

const PAGE: &str = "export default function Page() { return <main>Hi</main>; }\n";

#[test]
fn next_app_router_groups_slots_dynamic_and_api() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"next":"16.0.0","react":"19.0.0"}}"#,
        ),
        (
            "tsconfig.json",
            r#"{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}"#,
        ),
        (
            "src/app/layout.tsx",
            "export default function Root({children}) { return <html>{children}</html>; }",
        ),
        ("src/app/page.tsx", PAGE),
        ("src/app/(marketing)/about/page.tsx", PAGE),
        ("src/app/products/[id]/page.tsx", PAGE),
        ("src/app/docs/[...slug]/page.mdx", "# Docs"),
        ("src/app/shop/[[...filters]]/page.tsx", PAGE),
        ("src/app/photo/[id]/page.tsx", PAGE),
        ("src/app/@modal/(.)photo/[id]/page.tsx", PAGE),
        (
            "src/app/@modal/default.tsx",
            "export default function D() { return null }",
        ),
        ("src/app/_components/page.tsx", PAGE),
        ("src/app/not-found.tsx", PAGE),
        (
            "src/app/api/orders/route.ts",
            "import x from 'y';\nexport async function GET() {}\nexport const POST = async () => {};\n",
        ),
        (
            "src/app/[view]/page.tsx",
            "export function generateStaticParams() {\n  return [\"universe\", \"settings\"].map((view) => ({ view }));\n}\nexport default function Page() { return <div/>; }\n",
        ),
        (
            "src/app/services/[slug]/page.tsx",
            "import { services } from \"@/lib/services\";\nexport function generateStaticParams() {\n  return services.map((service) => ({ slug: service.slug }));\n}\nexport default function Page() { return <div/>; }\n",
        ),
        (
            "src/lib/services.ts",
            "export type Service = { slug: string };\nexport const services: Service[] = [\n  { slug: \"home-inspection\", title: \"A\" },\n  { slug: 'radon-testing', title: \"B\" },\n];\n",
        ),
        (
            "src/app/old/page.tsx",
            "import { redirect } from 'next/navigation';\nexport default function Old() { redirect('/new'); }\n",
        ),
        ("node_modules/next/app/page.tsx", PAGE),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "nextjs-app");
    assert!(!d.hash_routing);
    assert_eq!(d.app_dir, "");
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/:view",
            "/about",
            "/docs/:slug+",
            "/photo/:id",
            "/products/:id",
            "/services/:slug",
            "/shop/:filters*",
        ]
    );
    let about = route(&d, "/about", "page");
    assert_eq!(about.file, "src/app/(marketing)/about/page.tsx");
    assert_eq!(about.line, 1);
    assert!(!about.dynamic);
    assert!(route(&d, "/products/:id", "page").dynamic);
    let api = route(&d, "/api/orders", "api");
    assert_eq!(api.methods, vec!["GET", "POST"]);
    assert_eq!(api.line, 2);
    assert_eq!(route(&d, "/", "layout").file, "src/app/layout.tsx");
    assert_eq!(route(&d, "/old", "redirect").file, "src/app/old/page.tsx");
    assert_eq!(
        route(&d, "/:view", "page").examples,
        vec!["/settings", "/universe"]
    );
    assert_eq!(
        route(&d, "/services/:slug", "page").examples,
        vec!["/services/home-inspection", "/services/radon-testing"]
    );

    assert_eq!(
        seed_paths(&d),
        vec![
            "/",
            "/about",
            "/services/home-inspection",
            "/services/radon-testing",
            "/settings",
            "/shop",
            "/universe",
        ]
    );
}

#[test]
fn next_pages_router_with_base_path_and_trailing_slash() {
    let dir = tree(&[
        ("package.json", r#"{"dependencies":{"next":"14.2.0"}}"#),
        (
            "next.config.js",
            "module.exports = {\n  // basePath: '/ignored',\n  basePath: '/docs',\n  trailingSlash: true,\n};\n",
        ),
        ("pages/_app.tsx", PAGE),
        ("pages/_document.tsx", PAGE),
        ("pages/index.tsx", PAGE),
        ("pages/404.tsx", PAGE),
        ("pages/about/team.tsx", PAGE),
        (
            "pages/blog/[slug].tsx",
            "export async function getStaticPaths() {\n  return { paths: [{ params: { slug: 'hello' } }, { params: { slug: \"world\" } }], fallback: false };\n}\nexport default function Post() { return <article/>; }\n",
        ),
        (
            "pages/api/hello.ts",
            "export default function handler(req, res) { res.json({}) }",
        ),
        (
            "pages/api/users/[id].ts",
            "export default function handler(req, res) { res.json({}) }",
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "nextjs-pages");
    assert_eq!(d.base_path, "/docs");
    assert!(d.trailing_slash);
    assert_eq!(
        page_paths(&d),
        vec!["/docs", "/docs/about/team", "/docs/blog/:slug"]
    );
    assert_eq!(route(&d, "/docs/404", "error").file, "pages/404.tsx");
    // Enumerated by getStaticPaths: seeded, not sampled as a template.
    assert!(route_templates(&d).is_empty());
    assert_eq!(
        route(&d, "/docs/api/users/:id", "api").file,
        "pages/api/users/[id].ts"
    );
    assert_eq!(
        route(&d, "/docs/blog/:slug", "page").examples,
        vec!["/docs/blog/hello", "/docs/blog/world"]
    );
    assert_eq!(
        seed_paths(&d),
        vec![
            "/docs/",
            "/docs/about/team/",
            "/docs/blog/hello/",
            "/docs/blog/world/"
        ]
    );
}

#[test]
fn astro_pages_endpoints_and_static_paths() {
    let dir = tree(&[
        ("package.json", r#"{"dependencies":{"astro":"5.0.0"}}"#),
        (
            "astro.config.mjs",
            "export default defineConfig({ site: 'https://x.test', trailingSlash: 'never' });",
        ),
        ("src/pages/index.astro", "---\n---\n<h1>Home</h1>"),
        ("src/pages/about.astro", "<h1>About</h1>"),
        ("src/pages/404.astro", "<h1>Missing</h1>"),
        ("src/pages/_draft.astro", "<h1>Draft</h1>"),
        ("src/pages/guides/intro.md", "# Intro"),
        (
            "src/pages/blog/[slug].astro",
            "---\nexport function getStaticPaths() {\n  return [{ params: { slug: 'first' } }, { params: { slug: 'second' } }];\n}\n---\n<article/>",
        ),
        ("src/pages/docs/[...path].astro", "<div/>"),
        (
            "src/pages/rss.xml.ts",
            "export const GET = () => new Response('')",
        ),
        ("src/components/Nav.astro", "<nav/>"),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "astro");
    assert!(!d.trailing_slash);
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/about",
            "/blog/:slug",
            "/docs/:path*",
            "/guides/intro"
        ]
    );
    // 404.astro is an error page: not a route, never `/:id`, never seeded.
    assert_eq!(route(&d, "/404", "error").file, "src/pages/404.astro");
    assert_eq!(route_templates(&d), vec!["/docs/:path*"]);
    assert_eq!(route(&d, "/rss.xml", "api").methods, vec!["GET"]);
    assert_eq!(
        seed_paths(&d),
        vec![
            "/",
            "/about",
            "/blog/first",
            "/blog/second",
            "/docs",
            "/guides/intro"
        ]
    );
}

#[test]
fn sveltekit_routes_groups_and_endpoints() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"devDependencies":{"@sveltejs/kit":"2.0.0"}}"#,
        ),
        (
            "svelte.config.js",
            "export default { kit: { paths: { base: '/app' } } };",
        ),
        ("src/routes/+layout.svelte", "<slot/>"),
        ("src/routes/+page.svelte", "<h1/>"),
        ("src/routes/(auth)/login/+page.svelte", "<h1/>"),
        ("src/routes/blog/[slug]/+page.svelte", "<h1/>"),
        (
            "src/routes/blog/[slug]/+page.ts",
            "export const load = () => ({})",
        ),
        ("src/routes/[[lang]]/pricing/+page.svelte", "<h1/>"),
        (
            "src/routes/api/items/+server.ts",
            "export async function GET() {}\nexport async function POST() {}",
        ),
        ("src/lib/Button.svelte", "<button/>"),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "sveltekit");
    assert_eq!(d.base_path, "/app");
    assert_eq!(
        page_paths(&d),
        vec![
            "/app",
            "/app/:lang?/pricing",
            "/app/blog/:slug",
            "/app/login"
        ]
    );
    assert_eq!(
        route(&d, "/app/api/items", "api").methods,
        vec!["GET", "POST"]
    );
    assert_eq!(
        route(&d, "/app", "layout").file,
        "src/routes/+layout.svelte"
    );
    assert_eq!(seed_paths(&d), vec!["/app", "/app/login", "/app/pricing"]);
}

#[test]
fn remix_flat_routes_conventions() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"@remix-run/react":"^2.9.0"}}"#,
        ),
        ("app/root.tsx", PAGE),
        ("app/routes/_index.tsx", PAGE),
        ("app/routes/about.tsx", PAGE),
        ("app/routes/concerts.tsx", PAGE),
        ("app/routes/concerts._index.tsx", PAGE),
        ("app/routes/concerts.$city.tsx", PAGE),
        ("app/routes/concerts_.mine.tsx", PAGE),
        ("app/routes/_auth.tsx", PAGE),
        ("app/routes/_auth.login.tsx", PAGE),
        ("app/routes/files.$.tsx", PAGE),
        (
            "app/routes/sitemap[.]xml.tsx",
            "export const loader = () => new Response('')",
        ),
        ("app/routes/dashboard/route.tsx", PAGE),
        (
            "app/routes/dashboard/chart.tsx",
            "export function Chart() {}",
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "remix");
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/about",
            "/concerts",
            "/concerts/:city",
            "/concerts/mine",
            "/dashboard",
            "/files/*",
            "/login",
        ]
    );
    assert_eq!(
        route(&d, "/concerts", "page").file,
        "app/routes/concerts._index.tsx"
    );
    assert_eq!(
        route(&d, "/concerts", "layout").file,
        "app/routes/concerts.tsx"
    );
    assert_eq!(route(&d, "/", "layout").file, "app/routes/_auth.tsx");
    assert_eq!(
        route(&d, "/sitemap.xml", "api").file,
        "app/routes/sitemap[.]xml.tsx"
    );
    assert_eq!(
        route(&d, "/dashboard", "page").file,
        "app/routes/dashboard/route.tsx"
    );
}

#[test]
fn react_router_v7_routes_config() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router":"7.1.0","@react-router/dev":"7.1.0"}}"#,
        ),
        (
            "app/routes.ts",
            r#"import { type RouteConfig, index, route, layout, prefix } from "@react-router/dev/routes";
export default [
  index("routes/home.tsx"),
  route("about", "routes/about.tsx"),
  layout("routes/auth/layout.tsx", [
    route("login", "routes/auth/login.tsx"),
  ]),
  ...prefix("concerts", [
    index("routes/concerts/home.tsx"),
    route(":city", "routes/concerts/city.tsx", [route("tickets", "routes/concerts/tickets.tsx")]),
  ]),
  route("healthz", "routes/healthz.ts"),
] satisfies RouteConfig;
"#,
        ),
        ("app/routes/home.tsx", PAGE),
        ("app/routes/about.tsx", PAGE),
        ("app/routes/auth/layout.tsx", PAGE),
        ("app/routes/auth/login.tsx", PAGE),
        ("app/routes/concerts/home.tsx", PAGE),
        ("app/routes/concerts/city.tsx", PAGE),
        ("app/routes/concerts/tickets.tsx", PAGE),
        (
            "app/routes/healthz.ts",
            "export const loader = () => new Response('ok')",
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "remix");
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/about",
            "/concerts",
            "/concerts/:city",
            "/concerts/:city/tickets",
            "/login"
        ]
    );
    assert_eq!(
        route(&d, "/login", "page").file,
        "app/routes/auth/login.tsx"
    );
    assert_eq!(route(&d, "/healthz", "api").file, "app/routes/healthz.ts");
}

#[test]
fn react_router_jsx_and_object_routes() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"6.22.0","vite":"5.0.0"}}"#,
        ),
        ("index.html", "<div id=root></div>"),
        (
            "src/App.tsx",
            r#"import { Routes, Route, Navigate } from "react-router-dom";
const DEV_PATH = "/dev/bench";
export function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/settings" element={<Layout />}>
        <Route index element={<Profile />} />
        <Route path="billing" element={<Billing title="Don't panic" />} />
        <Route path="/settings/team/:teamId" element={<Team />} />
      </Route>
      <Route element={<Shell />}>
        <Route path="reports" element={<Reports />} />
      </Route>
      <Route path={DEV_PATH} element={<Bench />} />
      <Route path={dynamicPath()} element={<X />} />
      <Route path="/old" element={<Navigate to="/" replace />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
"#,
        ),
        (
            "src/main.tsx",
            r#"import { createBrowserRouter } from "react-router-dom";
import { adminRoutes } from "./admin-routes";
const router = createBrowserRouter([
  { path: "/app", element: <App />, children: [
    { index: true, element: <Dash /> },
    { path: "items/:itemId", element: <Item /> },
    ...adminRoutes,
  ] },
]);
"#,
        ),
        (
            "src/admin-routes.tsx",
            r#"import type { RouteObject } from "react-router-dom";
export const adminRoutes: RouteObject[] = [{ path: "admin", element: <Admin /> }];
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "react-router");
    assert!(!d.hash_routing);
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/app",
            "/app/admin",
            "/app/items/:itemId",
            "/dev/bench",
            "/reports",
            "/settings",
            "/settings/billing",
            "/settings/team/:teamId",
        ]
    );
    assert_eq!(route(&d, "/old", "redirect").file, "src/App.tsx");
    assert_eq!(route(&d, "/settings/billing", "page").line, 9);
    assert_eq!(route(&d, "/app/admin", "page").file, "src/admin-routes.tsx");
    assert_eq!(d.notes.len(), 1, "{:?}", d.notes);
    assert!(d.notes[0].contains("src/App.tsx:16"), "{:?}", d.notes);
}

#[test]
fn react_router_conditional_factory_alias_and_route_branches() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/App.tsx",
            r#"import { createBrowserRouter, createHashRouter } from "react-router-dom";
const createSellerRouter = isNative(window) ? createHashRouter : createBrowserRouter;
const devRoutes = Fixture === null ? [] : [{ path: "dev/grading-fixture", element: <Fixture /> }];
const workflowRoute = DevWorkflow === null ? null : { path: "dev/workflow", element: <Workflow /> };
const apiData = [{ path: "/api/not-a-route", element: "data" }];
const router = createSellerRouter([{ path: "/", element: <Shell />, children: [
  { index: true, element: <Dashboard /> },
  { path: "device-test", element: <Test /> },
  { path: "devices", element: <Devices /> },
  { path: "devices/:deviceId", element: <Devices /> },
  { path: "labels/:deviceId", element: <Labels /> },
  { path: "selling", element: <Selling /> },
  { path: "selling/review", element: <Review /> },
  { path: "selling/:orderId", element: <Selling /> },
  { path: "prices", element: <Prices /> },
  { path: "account", element: <Account /> },
  ...devRoutes,
  { path: "*", element: <NotFound /> },
]}]);
export function App() {
  if (workflowRoute !== null && window.location.pathname === `/${workflowRoute.path}`) return workflowRoute.element;
  return <RouterProvider router={router} />;
}
"#,
        ),
    ]);
    let d = discover(&dir);
    assert!(
        !d.hash_routing,
        "browser/native choice is not proof of hash routing"
    );
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/account",
            "/dev/grading-fixture",
            "/device-test",
            "/devices",
            "/devices/:deviceId",
            "/labels/:deviceId",
            "/prices",
            "/selling",
            "/selling/:orderId",
            "/selling/review",
        ]
    );
    assert_eq!(route(&d, "/dev/grading-fixture", "page").line, 3);
    assert!(
        d.notes
            .iter()
            .any(|note| note.contains("select browser or hash"))
    );
    assert!(
        d.notes
            .iter()
            .any(|note| note.contains("conditional route branches"))
    );
    // A standalone pathname/render guard still needs an explicit seed. It
    // must not justify collecting every path-bearing data object in a file.
    assert!(!page_paths(&d).contains(&"/dev/workflow"));
}

#[test]
fn react_router_import_alias_and_const_chain_preserve_pure_hash_history() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { createHashRouter as hash, createBrowserRouter } from "react-router-dom";
const first = hash;
const makeRouter = enabled ? first : hash;
const routes = [{ path: "/", element: <Home /> }, { path: "/items/:id", element: <Item /> }];
const router = makeRouter(routes);
"#,
        ),
    ]);
    let d = discover(&dir);
    assert!(d.hash_routing);
    assert_eq!(page_paths(&d), vec!["/#/", "/#/items/:id"]);
    assert_eq!(seed_paths(&d), vec!["/#/"]);
}

#[test]
fn react_router_does_not_infer_factories_from_names_or_path_data() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { Link, createBrowserRouter as browser, createHashRouter } from "react-router-dom";
import { createBrowserRouter as unrelated } from "./api";
const custom = native ? createArbitraryRouter : browser;
custom([{ path: "/unproven-factory", element: <Page /> }]);
unrelated([{ path: "/api-data", element: <Page /> }]);
createArbitraryRouter([{ path: "/unimported", element: <Page /> }]);
const ordinaryData = enabled ? [{ path: "/not-consumed", element: <Page /> }] : [];
const example = 'browser([{ path: "/inside-string", element: null }])';
const router = browser([{ path: "/real", element: <Page /> }]);
"#,
        ),
        (
            "src/api.ts",
            "export function createBrowserRouter(data) { return data; }",
        ),
    ]);
    let d = discover(&dir);
    assert!(
        !d.hash_routing,
        "an unused hash factory import is not an active router"
    );
    assert_eq!(page_paths(&d), vec!["/real"]);
}

#[test]
fn react_router_nested_conditional_arrays_remain_scoped_to_router_children() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { createBrowserRouter } from "react-router-dom";
const selected = first ? (second ? [{ path: "one", element: <One /> }] : [{ path: "two", element: <Two /> }]) : [];
const router = createBrowserRouter([{ path: "/app", element: <Shell />, children: [
  ...selected,
  ...(ready?.flag ? [{ path: "optional", element: <Optional /> }] : []),
]}]);
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(
        page_paths(&d),
        vec!["/app", "/app/one", "/app/optional", "/app/two"]
    );
}

#[test]
fn react_router_namespace_factories_require_a_router_import() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import * as RR from 'react-router-dom';
import * as Data from './data';
const router = RR . createBrowserRouter([{ path: "/real", element: <Page /> }]);
Data.createBrowserRouter([{ path: "/data", element: <Page /> }]);
Unbound.createHashRouter([{ path: "/unbound", element: <Page /> }]);
"#,
        ),
        (
            "src/data.ts",
            "export function createBrowserRouter(data) { return data; }",
        ),
    ]);
    let d = discover(&dir);
    assert!(!d.hash_routing);
    assert_eq!(page_paths(&d), vec!["/real"]);

    let hash = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import * as Router from 'react-router-dom';
const factory = Router.createHashRouter;
const router = factory([{ path: "/", element: <Home /> }, { path: "/items/:id", element: <Item /> }]);
"#,
        ),
    ]);
    let d = discover(&hash);
    assert!(d.hash_routing);
    assert_eq!(page_paths(&d), vec!["/#/", "/#/items/:id"]);
}

#[test]
fn react_router_commonjs_namespace_and_named_bindings_remain_supported() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"const RR = require('react-router-dom');
const { createHashRouter: hash } = require('react-router-dom');
const Data = require('./data');
const router = RR.createHashRouter([{ path: "/", element: <Home /> }]);
const second = hash([{ path: "/items/:id", element: <Item /> }]);
Data.createBrowserRouter([{ path: "/not-a-route", element: 'data' }]);
"#,
        ),
    ]);
    let d = discover(&dir);
    assert!(d.hash_routing);
    assert_eq!(page_paths(&d), vec!["/#/", "/#/items/:id"]);
}

#[test]
fn react_router_import_examples_cannot_establish_factory_bindings() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { createBrowserRouter as browser } from 'react-router-dom';
const example = "import { createBrowserRouter as make } from 'react-router-dom'";
const example2 = `const Fake = require('react-router-dom')`;
const make = value => value;
make([{ path: '/data', element: 'data' }]);
Fake.createHashRouter([{ path: '/fake', element: 'data' }]);
const router = browser([{ path: '/real', element: <Page /> }]);
"#,
        ),
    ]);
    let d = discover(&dir);
    assert!(!d.hash_routing);
    assert_eq!(page_paths(&d), vec!["/real"]);
}

#[test]
fn react_router_shadowed_aliases_are_omitted_without_losing_other_bindings() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { createBrowserRouter as browser } from 'react-router-dom';
const makeRouter = browser;
function transform(makeRouter) { return makeRouter([{ path: '/data', element: 'data' }]); }
const router = makeRouter([{ path: '/ambiguous', element: <Page /> }]);
const nested = browser;
const transform2 = (nested) => nested([{ path: '/arrow-data', element: 'data' }]);
const duplicate = browser;
function transform3() { const duplicate = x => x; return duplicate([{path: '/duplicate-data', element: 'data'}]); }
const unaffected = browser([{ path: '/real', element: <Page /> }]);
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(page_paths(&d), vec!["/real"]);
    for name in ["makeRouter", "nested", "duplicate"] {
        assert!(
            d.notes
                .iter()
                .any(|n| n.contains(name) && n.contains("routes omitted")),
            "{:?}",
            d.notes
        );
    }
}

#[test]
fn react_router_imports_shadowed_by_inner_declarations_are_omitted() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"7.1.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { createBrowserRouter as browser, createBrowserRouter as real } from 'react-router-dom';
import * as RR from 'react-router-dom';
function transform() { function browser(data) { return data; } return browser([{path:'/data',element:'data'}]); }
function namespace() { class RR { static createBrowserRouter(data) { return data; } } return RR.createBrowserRouter([{path:'/class-data',element:'data'}]); }
const router = real([{path:'/real',element:<Page />}]);
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(page_paths(&d), vec!["/real"]);
    assert!(
        d.notes
            .iter()
            .any(|n| n.contains("`browser`") && n.contains("routes omitted"))
    );
    assert!(
        d.notes
            .iter()
            .any(|n| n.contains("`RR`") && n.contains("routes omitted"))
    );
}

#[test]
fn react_router_hash_routing_prefixes_paths_and_seeds() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"react-router-dom":"6.22.0"}}"#,
        ),
        (
            "src/main.tsx",
            r#"import { createHashRouter } from "react-router-dom";
const routes = [{ path: "/", element: <Home /> }, { path: "/admin", element: <Admin /> }, { path: "/users/:id", element: <User /> }];
export const router = createHashRouter(routes);
"#,
        ),
        ("public/privacy.html", "<h1>Privacy</h1>"),
    ]);
    let d = discover(&dir);
    assert!(d.hash_routing);
    assert_eq!(
        page_paths(&d),
        vec!["/#/", "/#/admin", "/#/users/:id", "/privacy.html"]
    );
    assert_eq!(seed_paths(&d), vec!["/#/", "/#/admin", "/privacy.html"]);
}

#[test]
fn vue_router_hash_history_children_and_redirects() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"vue":"3.4.0","vue-router":"4.3.0"}}"#,
        ),
        (
            "src/router/index.ts",
            r#"import { createRouter, createWebHashHistory } from 'vue-router'
import routes from './routes'
export default createRouter({ history: createWebHashHistory(), routes })
"#,
        ),
        (
            "src/router/routes.ts",
            r#"export default [
  { path: '/', component: () => import('../views/Home.vue') },
  { path: '/user/:id(\\d+)', component: User, children: [
    { path: '', component: UserHome },
    { path: 'profile', component: UserProfile },
  ] },
  { path: '/home', redirect: '/' },
  { path: '/:pathMatch(.*)*', component: NotFound },
]
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "vue-router");
    assert!(d.hash_routing);
    assert_eq!(
        page_paths(&d),
        vec!["/#/", "/#/user/:id", "/#/user/:id/profile"]
    );
    assert_eq!(
        route(&d, "/#/home", "redirect").file,
        "src/router/routes.ts"
    );
    assert_eq!(seed_paths(&d), vec!["/#/"]);
}

#[test]
fn angular_routes_lazy_children_and_hash_location() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"@angular/core":"18.0.0","@angular/router":"18.0.0"}}"#,
        ),
        ("src/index.html", "<base href=\"/\"><app-root></app-root>"),
        (
            "src/app/app.config.ts",
            "import { provideRouter, withHashLocation } from '@angular/router';\nimport { routes } from './app.routes';\nexport const appConfig = { providers: [provideRouter(routes, withHashLocation())] };\n",
        ),
        (
            "src/app/app.routes.ts",
            r#"import { Routes } from '@angular/router';
export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'admin', loadChildren: () => import('./admin/admin.routes').then(m => m.ADMIN_ROUTES) },
  { path: 'old', redirectTo: 'login', pathMatch: 'full' },
  { path: '**', component: NotFoundComponent },
];
"#,
        ),
        (
            "src/app/admin/admin.routes.ts",
            r#"import { Routes } from '@angular/router';
export const ADMIN_ROUTES: Routes = [
  { path: '', component: AdminHome },
  { path: 'users/:id', component: AdminUser },
];
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "angular");
    assert!(d.hash_routing);
    assert_eq!(
        page_paths(&d),
        vec!["/#/", "/#/admin", "/#/admin/users/:id", "/#/login"]
    );
    assert_eq!(
        route(&d, "/#/admin", "page").file,
        "src/app/admin/admin.routes.ts"
    );
    assert_eq!(route(&d, "/#/old", "redirect").kind, "redirect");
}

#[test]
fn angular_router_module_for_root_with_use_hash() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"@angular/core":"16.0.0","@angular/router":"16.0.0"}}"#,
        ),
        (
            "src/index.html",
            "<base href=\"/portal/\"><app-root></app-root>",
        ),
        (
            "src/app/app-routing.module.ts",
            r#"import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
@NgModule({
  imports: [RouterModule.forRoot([
    { path: '', component: HomeComponent },
    { path: 'reports', component: ReportsComponent, children: [{ path: ':id', component: ReportComponent }] },
  ], { useHash: true })],
})
export class AppRoutingModule {}
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "angular");
    assert!(d.hash_routing);
    assert_eq!(d.base_path, "/portal");
    assert_eq!(
        page_paths(&d),
        vec!["/portal/#/", "/portal/#/reports", "/portal/#/reports/:id"]
    );
    assert_eq!(seed_paths(&d), vec!["/portal/#/", "/portal/#/reports"]);
}

#[test]
fn hono_server_routes_mounts_and_page_detection() {
    let dir = tree(&[
        ("package.json", r#"{"dependencies":{"hono":"4.0.0"}}"#),
        (
            "src/index.tsx",
            r#"import { Hono } from 'hono';
import admin from './routes/admin';
import { api } from './routes/api';
import help from './routes/help';
const app = new Hono<Env>();
app.use('*', logger());
app.get('/', (c) => c.html(<Home />));
app.get('/about', (c) => aboutPage(c));
app.post('/contact', async (c) => { await save(c); return c.redirect('/thanks'); });
app.get('/robots.txt', (c) => c.text('User-agent: *'));
app.get('/media/:file{.+}', async (c) => {
  if (!c.req.param('file')) return c.text('Not found', 404);
  return serveImage(c.env, c.req.param('file'));
});
app.route('/admin', admin);
app.route('/api', api);
app.route('/', help);
app.get('*', (c) => c.notFound());
export default app;

function aboutPage(c) {
  return render(c, <Layout title="About" />);
}
"#,
        ),
        (
            "src/routes/admin.tsx",
            r#"import { Hono } from 'hono';
import { adminPage } from '../views/admin';
const app = new Hono();
app.get('/', (c) => adminPage(c, 'Dashboard'));
app.get('/bookings/:id', async (c) => {
  if (!ok) return c.redirect('/admin/login');
  return c.html(<Booking />);
});
app.on(['GET', 'POST'], '/login', (c) => c.html(<Login />));
export default app;
"#,
        ),
        (
            "src/routes/api.ts",
            r#"import { Hono } from 'hono';
export const api = new Hono().basePath('/v1').get('/quote', (c) => c.json({})).post('/quote', (c) => c.json({}));
"#,
        ),
        (
            "src/views/admin.tsx",
            "export function adminPage(c, title) {\n  return c.html(<Shell title={title} />);\n}\n",
        ),
        (
            "src/routes/help.ts",
            r#"import { Hono } from 'hono';
import { html } from 'hono/html';
const help = new Hono();
const helpPage = (c) => c.html(html`<h1>Help</h1>`);
help.get('/help', helpPage);
help.get('/help/feed', feed);
export default help;
function feed(c) {
  return c.json([]);
}
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "hono");
    assert_eq!(
        page_paths(&d),
        vec![
            "/",
            "/about",
            "/admin",
            "/admin/bookings/:id",
            "/admin/login",
            "/help",
        ]
    );
    assert_eq!(route(&d, "/help", "page").file, "src/routes/help.ts");
    assert_eq!(route(&d, "/help/feed", "api").line, 6);
    assert_eq!(route(&d, "/contact", "api").methods, vec!["POST"]);
    assert_eq!(route(&d, "/robots.txt", "api").methods, vec!["GET"]);
    assert_eq!(route(&d, "/media/:file", "api").file, "src/index.tsx");
    assert_eq!(route(&d, "/admin/login", "api").methods, vec!["POST"]);
    assert_eq!(route(&d, "/admin/login", "page").methods, vec!["GET"]);
    let quote = route(&d, "/api/v1/quote", "api");
    assert_eq!(quote.methods, vec!["GET", "POST"]);
    assert_eq!(quote.file, "src/routes/api.ts");
    assert_eq!(route(&d, "/about", "page").line, 8);
    assert_eq!(
        route(&d, "/admin/bookings/:id", "page").file,
        "src/routes/admin.tsx"
    );
    assert_eq!(
        seed_paths(&d),
        vec!["/", "/about", "/admin", "/admin/login", "/help"]
    );
}

#[test]
fn express_routers_route_chains_and_requires() {
    let dir = tree(&[
        ("package.json", r#"{"dependencies":{"express":"4.19.0"}}"#),
        (
            "server/index.js",
            r#"const express = require('express');
const users = require('./users');
const app = express();
app.set('port', 3000);
app.get('env');
app.use(express.json());
app.use('/users', users);
app.use('/legacy', require('./legacy'));
app.get('/', (req, res) => res.render('home'));
app.get(['/health', '/healthz'], (req, res) => res.json({ ok: true }));
app.route('/book').get((req, res) => res.send('<h1>Book</h1>')).post((req, res) => res.sendStatus(201));
module.exports = app;
"#,
        ),
        (
            "server/users.js",
            r#"const { Router } = require('express');
const router = Router();
router.get('/', (req, res) => res.json([]));
router.get('/:id', (req, res) => res.render('user'));
router.delete('/:id', (req, res) => res.sendStatus(204));
module.exports = router;
"#,
        ),
        (
            "server/legacy.js",
            "const express = require('express');\nconst r = express.Router();\nr.get('/x', (req, res) => res.redirect('/'));\nmodule.exports = r;\n",
        ),
        ("public/index.html", "<h1>App</h1>"),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "express");
    assert_eq!(page_paths(&d), vec!["/", "/book", "/users/:id"]);
    assert_eq!(route(&d, "/", "page").file, "public/index.html");
    assert_eq!(route(&d, "/health", "api").methods, vec!["GET"]);
    assert_eq!(route(&d, "/healthz", "api").methods, vec!["GET"]);
    assert_eq!(route(&d, "/book", "api").methods, vec!["POST"]);
    assert_eq!(route(&d, "/users", "api").file, "server/users.js");
    assert_eq!(route(&d, "/users/:id", "api").methods, vec!["DELETE"]);
    assert_eq!(route(&d, "/legacy/x", "redirect").file, "server/legacy.js");
}

#[test]
fn fastify_plugins_register_with_prefix() {
    let dir = tree(&[
        ("package.json", r#"{"dependencies":{"fastify":"4.0.0"}}"#),
        (
            "src/server.ts",
            "import Fastify from 'fastify';\nimport users from './users';\nconst app = Fastify({ logger: true });\napp.register(users, { prefix: '/users' });\napp.route({ method: 'GET', url: '/status', handler: async () => ({ ok: true }) });\n",
        ),
        (
            "src/users.ts",
            "import type { FastifyInstance } from 'fastify';\nexport default async function (fastify: FastifyInstance) {\n  fastify.get('/', async () => []);\n  fastify.post('/:id', async () => ({}));\n}\n",
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "fastify");
    assert_eq!(route(&d, "/users", "api").file, "src/users.ts");
    assert_eq!(route(&d, "/users/:id", "api").methods, vec!["POST"]);
    assert_eq!(route(&d, "/status", "api").methods, vec!["GET"]);
}

#[test]
fn tanstack_and_nuxt_file_routes() {
    let tanstack = tree(&[
        (
            "package.json",
            r#"{"dependencies":{"@tanstack/react-router":"1.0.0"}}"#,
        ),
        (
            "src/routes/__root.tsx",
            "export const Route = createRootRoute({})",
        ),
        (
            "src/routes/index.tsx",
            "export const Route = createFileRoute('/')({})",
        ),
        (
            "src/routes/posts.$postId.tsx",
            "export const Route = createFileRoute('/posts/$postId')({})",
        ),
        (
            "src/routes/_layout/settings.tsx",
            "export const Route = createFileRoute('/_layout/settings')({})",
        ),
    ]);
    let d = discover(&tanstack);
    assert_eq!(d.framework, "tanstack-router");
    assert_eq!(page_paths(&d), vec!["/", "/posts/:postId", "/settings"]);

    let nuxt = tree(&[
        ("package.json", r#"{"devDependencies":{"nuxt":"3.12.0"}}"#),
        ("pages/index.vue", "<template/>"),
        ("pages/users/[id].vue", "<template/>"),
        (
            "server/api/hello.get.ts",
            "export default defineEventHandler(() => 'hi')",
        ),
    ]);
    let d = discover(&nuxt);
    assert_eq!(d.framework, "nuxt");
    assert_eq!(page_paths(&d), vec!["/", "/users/:id"]);
    assert_eq!(route(&d, "/api/hello", "api").methods, vec!["GET"]);
}

#[test]
fn vite_spa_without_router_and_static_sites() {
    let vite = tree(&[
        ("package.json", r#"{"devDependencies":{"vite":"7.0.0"}}"#),
        (
            "vite.config.ts",
            "export default defineConfig({ base: '/studio/', plugins: [] })",
        ),
        ("index.html", "<div id=root></div>"),
        ("public/vite.svg", "<svg/>"),
        ("dist/index.html", "<div/>"),
    ]);
    let d = discover(&vite);
    assert_eq!(d.framework, "vite");
    assert_eq!(d.base_path, "/studio");
    assert_eq!(page_paths(&d), vec!["/studio"]);
    assert_eq!(seed_paths(&d), vec!["/studio"]);

    let plain = tree(&[("index.html", "<h1/>"), ("contact.html", "<h1/>")]);
    let d = discover(&plain);
    assert_eq!(d.framework, "static");
    assert_eq!(page_paths(&d), vec!["/", "/contact.html"]);

    let empty = tree(&[("README.md", "# nothing")]);
    let d = discover(&empty);
    assert_eq!(d.framework, "unknown");
    assert!(d.routes.is_empty());
    assert!(seed_paths(&d).is_empty());
}

#[test]
fn monorepo_root_picks_the_web_app() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"private":true,"devDependencies":{"turbo":"2.0.0"}}"#,
        ),
        (
            "apps/web/package.json",
            r#"{"dependencies":{"next":"16.0.0"}}"#,
        ),
        ("apps/web/app/page.tsx", PAGE),
        ("apps/web/app/pricing/page.tsx", PAGE),
        (
            "apps/api/package.json",
            r#"{"dependencies":{"express":"4.0.0"}}"#,
        ),
        (
            "apps/api/src/index.js",
            "const express = require('express');\nconst app = express();\napp.get('/v1/a', (q, s) => s.json({}));\napp.get('/v1/b', (q, s) => s.json({}));\napp.get('/v1/c', (q, s) => s.json({}));\n",
        ),
        (
            "packages/ui/package.json",
            r#"{"dependencies":{"react":"19.0.0"}}"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "nextjs-app");
    assert_eq!(d.app_dir, "apps/web");
    assert_eq!(
        route(&d, "/pricing", "page").file,
        "apps/web/app/pricing/page.tsx"
    );

    let direct = discover_routes(&dir.path().join("apps/web")).expect("discover app dir");
    assert_eq!(direct.app_dir, "");
    assert_eq!(
        route(&direct, "/pricing", "page").file,
        "app/pricing/page.tsx"
    );
}

#[test]
fn seed_paths_applies_base_and_hash_to_hand_built_discoveries() {
    let route = |path: &str, dynamic: bool, kind: &str| DiscoveredRoute {
        path: path.to_string(),
        dynamic,
        kind: kind.to_string(),
        file: "src/router.ts".to_string(),
        ..Default::default()
    };
    let d = RouteDiscovery {
        framework: "vue-router".to_string(),
        hash_routing: true,
        base_path: "/app".to_string(),
        routes: vec![
            route("/", false, "page"),
            route("/admin", false, "page"),
            route("/users/:id", true, "page"),
            route("/api/x", false, "api"),
        ],
        ..Default::default()
    };
    assert_eq!(seed_paths(&d), vec!["/app/#/", "/app/#/admin"]);
}

#[test]
fn missing_codebase_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = discover_routes(&dir.path().join("nope")).expect_err("missing dir");
    assert!(format!("{err:#}").contains("read codebase"));
}

#[test]
fn discovery_serializes_compactly() {
    let d = RouteDiscovery {
        framework: "astro".to_string(),
        routes: vec![DiscoveredRoute {
            path: "/".to_string(),
            kind: "page".to_string(),
            file: "src/pages/index.astro".to_string(),
            line: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    let json = serde_json::to_value(&d).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!({
            "framework": "astro",
            "hash_routing": false,
            "base_path": "",
            "routes": [{"path": "/", "dynamic": false, "kind": "page", "file": "src/pages/index.astro", "line": 1}],
        })
    );
    let back: RouteDiscovery = serde_json::from_value(json).expect("deserialize");
    assert_eq!(back, d);
}

#[test]
fn route_templates_list_sampled_dynamic_pages_only() {
    let page = |path: &str, examples: &[&str]| DiscoveredRoute {
        path: path.to_string(),
        dynamic: paths::is_dynamic(path),
        kind: "page".to_string(),
        file: "src/routes/pages.tsx".to_string(),
        line: 1,
        methods: Vec::new(),
        examples: examples.iter().map(|e| e.to_string()).collect(),
    };
    let mut d = RouteDiscovery {
        framework: "hono".into(),
        routes: vec![
            page("/", &[]),
            page("/dumpster-rental/:town", &[]),
            page("/equipment/:slug", &[]),
            page("/:slug", &[]),
            page("/:view", &["/universe", "/settings"]),
            page("/blog/:slug", &["/blog/first"]),
            DiscoveredRoute {
                kind: "api".into(),
                ..page("/api/availability/:slug", &[])
            },
            DiscoveredRoute {
                kind: "error".into(),
                ..page("/404", &[])
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        route_templates(&d),
        vec!["/dumpster-rental/:town", "/equipment/:slug"]
    );
    // Error pages are never seeded.
    assert!(!seed_paths(&d).contains(&"/404".to_string()));

    d.base_path = "/app".into();
    d.routes = vec![page("/app/:id", &[]), page("/app/items/:id", &[])];
    assert_eq!(route_templates(&d), vec!["/app/items/:id"]);

    d.base_path = String::new();
    d.hash_routing = true;
    d.routes = vec![page("/items/:id", &[])];
    assert_eq!(route_templates(&d), vec!["/#/items/:id"]);
}

#[test]
fn error_pages_are_not_page_routes_in_any_router() {
    let dir = tree(&[
        ("package.json", r#"{"dependencies":{"astro":"5.0.0"}}"#),
        ("src/pages/index.astro", "<h1>Home</h1>"),
        ("src/pages/500.astro", "<h1>Oops</h1>"),
        ("public/404.html", "<h1>Missing</h1>"),
    ]);
    let d = discover(&dir);
    assert_eq!(page_paths(&d), vec!["/"]);
    assert_eq!(route(&d, "/500", "error").file, "src/pages/500.astro");
    assert_eq!(seed_paths(&d), vec!["/"]);
}

#[test]
fn custom_location_hash_routes_discovered_in_vite_spa() {
    let dir = tree(&[
        (
            "package.json",
            r#"{"devDependencies":{"vite":"7.0.0"},"dependencies":{"react":"19.0.0"}}"#,
        ),
        ("index.html", "<div id=root></div>"),
        (
            "web/App.tsx",
            r#"
function parseHash() {
  const raw = window.location.hash.replace(/^#/, "");
  const [path] = raw.split("?");
  return { view: (path ? path : "today") };
}
export function App() {
  window.addEventListener("hashchange", () => {});
  const { view } = parseHash();
  const go = (id) => { window.location.hash = `operations?property=${id}`; };
  return (
    <div>
      {view === "today" && <div />}
      {view === "operations" && <div />}
      {view === "calendar" && <div />}
    </div>
  );
}
"#,
        ),
    ]);
    let d = discover(&dir);
    assert_eq!(d.framework, "vite");
    assert_eq!(page_paths(&d), vec!["/", "/#calendar", "/#operations"]);
    assert_eq!(seed_paths(&d), vec!["/", "/#calendar", "/#operations"]);
}
