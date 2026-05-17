use axum::http::HeaderValue;
use axum::response::Response;
use axum::{Router, response::IntoResponse, routing::get};

const OPENAPI_JSON: &str = include_str!("../../openapi.json");
const SWAGGER_HTML: &str = r##"<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Sikrypt API Docs</title>
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script>
            window.ui = SwaggerUIBundle({
                url: "/openapi.json",
                dom_id: "#swagger-ui",
                layout: "BaseLayout"
            });
        </script>
    </body>
</html>
"##;

async fn openapi_json() -> Response {
    let mut response = OPENAPI_JSON.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

async fn swagger_ui() -> Response {
    let mut response = SWAGGER_HTML.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

pub fn router() -> Router {
    Router::new()
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(swagger_ui))
}
