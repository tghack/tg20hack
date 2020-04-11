use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;

async fn backup(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_FOUND;

    match (req.method(), req.uri().path()) {
        // Store handler
        (&Method::POST, p) if p.starts_with("/store/") => {
            // Remove offensive characters (possibly redundant)
            // and store file in the storage directory
            let file_path = format!(
                "storage/{}",
                &p.trim_start_matches("/store/")
                    .replace("/", "")
                    .replace(".", "")
            );

            // Create file and dump body contents into it
            if let Ok(mut file) = File::create(file_path) {
                let full_body = hyper::body::to_bytes(req.into_body()).await?;
                if let Ok(_) = file.write_all(&full_body) {
                    *response.status_mut() = StatusCode::OK;
                }
            }
        }
        // Restore handler
        (&Method::GET, p) if p.starts_with("/restore/") => {
            // Remove offensive characters (possibly redundant)
            // and store file in the storage directory
            let file_path = format!(
                "storage/{}",
                &p.trim_start_matches("/restore/")
                    .replace("/", "")
                    .replace(".", "")
            );

            // Open file and return the contents
            if let Ok(mut file) = File::open(&file_path) {
                let mut contents = Vec::new();
                if let Ok(_) = file.read_to_end(&mut contents) {
                    *response.body_mut() = Body::from(contents);
                    *response.status_mut() = StatusCode::OK;
                }
            }
        }
        // No matchin handler
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    }

    Ok(response)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C signal handler");
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // A `Service` is needed for every connection, so this
    // creates one from our `hello_world` function
    let make_svc = make_service_fn(|_conn| {
        async {
            // service_fn converts our function into a `Service`
            Ok::<_, Infallible>(service_fn(backup))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    // Run the server foreveeeeer and ever!
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    }
}
