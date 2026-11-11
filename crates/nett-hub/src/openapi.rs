//! The OpenAPI document of the Hub API (ADR 0003, CLAUDE.md "API, protocol and database"),
//! generated from the handlers. `nett-hub openapi` prints it; `docs/api/openapi.json` is the
//! committed copy, and CI checks that it is current. Each operation names its permission scope
//! (`x-nett-scope`) and risk level (`x-nett-risk`).

use nett_proto::api::{
    Event, LinkRequest, LinkResponse, MachineStatus, Problem, PushResponse, StatusResponse,
};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "nett Hub API",
        description = "The API the signing tool `nett site` uses to link a site to its Hub, push it and read the machines' status (design/hub.md section 4). Errors are application/problem+json.",
        license(name = "MIT OR Apache-2.0"),
    ),
    paths(
        crate::api::link,
        crate::api::push,
        crate::api::status,
        crate::api::updates,
        crate::api::events,
        crate::gateway::connect,
    ),
    components(schemas(
        LinkRequest, LinkResponse, PushResponse, StatusResponse, MachineStatus, Event, Problem,
    )),
    modifiers(&OwnerToken),
)]
pub struct ApiDoc;

/// The site's owner token, `nett_tok_…`, sent as a bearer token (design/auth.md section 6).
struct OwnerToken;

impl Modify for OwnerToken {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "owner_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("The site's owner token from `nett site link`"))
                    .build(),
            ),
        );
    }
}

/// The document as committed in `docs/api/openapi.json`. Keys are sorted: utoipa keeps
/// extensions in a hash map, and the committed copy has to be the same on every run.
pub fn json() -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(ApiDoc::openapi())?;
    serde_json::to_string_pretty(&value).map(|mut s| {
        s.push('\n');
        s
    })
}

#[cfg(test)]
mod tests {
    /// CI fails when the committed document is stale: regenerate it with
    /// `cargo run -p nett-hub -- openapi > docs/api/openapi.json`.
    #[test]
    fn the_committed_document_is_current() {
        assert_eq!(
            super::json().expect("serializes"),
            include_str!("../../../docs/api/openapi.json"),
            "docs/api/openapi.json is stale; regenerate it with `cargo run -p nett-hub -- openapi > docs/api/openapi.json`"
        );
    }
}
