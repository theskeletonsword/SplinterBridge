//! Host-local gRPC client. No TCP endpoint, DNS, proxy or remote fallback.
use crate::review::*;
use hyper_util::rt::TokioIo;
use splinter_proto::local_review::{
    local_privacy_classifier_client::LocalPrivacyClassifierClient, ReviewRequest,
};
use std::{path::Path, time::Duration};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

pub struct UnixGrpcClassifier {
    client: LocalPrivacyClassifierClient<Channel>,
    rpc_deadline: Duration,
}

impl UnixGrpcClassifier {
    /// Use a socket in a protected directory. Verify the server OS UID on every
    /// connection, including reconnects. A local relay could still forward data;
    /// deployment policy must deny worker egress and mount no backend credentials.
    pub async fn connect(
        socket: &Path,
        expected_server_uid: u32,
        deadline: Duration,
    ) -> Result<Self, ClassifierFailure> {
        if !socket.is_absolute() || deadline.is_zero() || deadline > Duration::from_secs(120) {
            return Err(ClassifierFailure::Unavailable);
        }
        let socket = socket.to_path_buf();
        // URI is an HTTP/2 authority only: the connector ignores it and uses UDS.
        let endpoint = Endpoint::from_static("http://localhost")
            .connect_timeout(deadline)
            .timeout(deadline)
            .buffer_size(1);
        let channel = tokio::time::timeout(
            deadline,
            endpoint.connect_with_connector(service_fn(move |_| {
                let socket = socket.clone();
                async move {
                    let stream = UnixStream::connect(socket).await?;
                    if stream.peer_cred()?.uid() != expected_server_uid {
                        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                    }
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            })),
        )
        .await
        .map_err(|_| ClassifierFailure::Unavailable)?
        .map_err(|_| ClassifierFailure::Unavailable)?;
        Ok(Self::from_channel(channel, deadline))
    }

    fn from_channel(channel: Channel, deadline: Duration) -> Self {
        Self {
            client: LocalPrivacyClassifierClient::new(channel)
                .max_decoding_message_size(MAX_MODEL_RESPONSE_BYTES + 16)
                .max_encoding_message_size(512 * 1024),
            rpc_deadline: deadline,
        }
    }
}

impl SemanticClassifier for UnixGrpcClassifier {
    fn classify(&self, input: ReviewInput) -> ClassificationFuture<'_> {
        Box::pin(async move {
            let candidate_json =
                serde_json::to_vec(&input).map_err(|_| ClassifierFailure::InvalidResponse)?;
            if candidate_json.len() > 512 * 1024 - 16 {
                return Err(ClassifierFailure::InvalidResponse);
            }
            let mut request = tonic::Request::new(ReviewRequest { candidate_json });
            request.set_timeout(self.rpc_deadline);
            let mut client = self.client.clone();
            let response = client
                .classify(request)
                .await
                .map_err(|_| ClassifierFailure::Unavailable)?
                .into_inner();
            parse_semantic_report(&response.report_json)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use splinter_proto::local_review::{
        local_privacy_classifier_server::{LocalPrivacyClassifier, LocalPrivacyClassifierServer},
        ReviewResponse,
    };
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    };
    use tokio_stream::wrappers::UnixListenerStream;

    struct Worker(Arc<AtomicU8>);
    #[tonic::async_trait]
    impl LocalPrivacyClassifier for Worker {
        async fn classify(
            &self,
            request: tonic::Request<ReviewRequest>,
        ) -> Result<tonic::Response<ReviewResponse>, tonic::Status> {
            assert!(request.metadata().get("grpc-timeout").is_some());
            let input: serde_json::Value =
                serde_json::from_slice(&request.into_inner().candidate_json).unwrap();
            assert_eq!(input["policy_code"], REVIEW_POLICY_CODE);
            match self.0.load(Ordering::SeqCst) {
                1 => return Err(tonic::Status::internal("SECRET-worker-error")),
                2 => {
                    return Ok(tonic::Response::new(ReviewResponse {
                        report_json: vec![0; MAX_MODEL_RESPONSE_BYTES + 100],
                    }))
                }
                3 => return std::future::pending().await,
                _ => (),
            }
            let fields: Vec<_> = input["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "field": f["field"], "decision": "ALLOW", "confidence_bps": 10000
                    })
                })
                .collect();
            Ok(tonic::Response::new(ReviewResponse {
                report_json: serde_json::to_vec(&serde_json::json!({"fields":fields})).unwrap(),
            }))
        }
    }
    fn input() -> ReviewInput {
        ReviewInput {
            policy_code: REVIEW_POLICY_CODE,
            origin: 1,
            destination: 2,
            fields: vec![ReviewText {
                field: ReviewField::Handle,
                text: "@fixture".into(),
            }],
        }
    }

    #[tokio::test]
    #[ignore = "Requires OS Unix-domain sockets; run explicitly in Linux CI"]
    async fn unix_transport_checks_peer_uid_deadlines_size_and_redacts_failures() {
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::env::temp_dir().join(format!(
            "splinter-uds-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let socket = directory.join("review.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let uid = UnixStream::pair().unwrap().0.peer_cred().unwrap().uid();
        let mode = Arc::new(AtomicU8::new(0));
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        let service = LocalPrivacyClassifierServer::new(Worker(mode.clone()))
            .max_decoding_message_size(512 * 1024);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                    let _ = stop.await;
                })
                .await
                .unwrap();
        });
        let deadline = Duration::from_millis(100);
        assert!(UnixGrpcClassifier::connect(&socket, uid ^ 1, deadline)
            .await
            .is_err());
        assert!(
            UnixGrpcClassifier::connect(Path::new("relative.sock"), uid, deadline)
                .await
                .is_err()
        );
        let client = UnixGrpcClassifier::connect(&socket, uid, deadline)
            .await
            .unwrap();
        assert_eq!(
            client.classify(input()).await.unwrap().fields[0].decision,
            SemanticDecision::Allow
        );
        for failure in 1..=3 {
            mode.store(failure, Ordering::SeqCst);
            let error = tokio::time::timeout(Duration::from_secs(2), client.classify(input()))
                .await
                .unwrap()
                .unwrap_err();
            assert!(!format!("{error:?}").contains("SECRET"));
        }
        drop(client);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn grpc_in_memory_validates_reports_limits_errors_and_deadlines() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let mode = Arc::new(AtomicU8::new(0));
        let service = LocalPrivacyClassifierServer::new(Worker(mode.clone()))
            .max_decoding_message_size(512 * 1024);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(server_io)))
                .await
                .unwrap();
        });
        let mut client_io = Some(client_io);
        let deadline = Duration::from_millis(100);
        let channel = Endpoint::from_static("http://localhost")
            .timeout(deadline)
            .connect_with_connector(service_fn(move |_| {
                let io = client_io.take();
                async move {
                    io.map(TokioIo::new)
                        .ok_or(std::io::Error::from(std::io::ErrorKind::NotConnected))
                }
            }))
            .await
            .unwrap();
        let client = UnixGrpcClassifier::from_channel(channel, deadline);
        assert_eq!(
            client.classify(input()).await.unwrap().fields[0].decision,
            SemanticDecision::Allow
        );
        for failure in 1..=3 {
            mode.store(failure, Ordering::SeqCst);
            let error = tokio::time::timeout(Duration::from_secs(2), client.classify(input()))
                .await
                .unwrap()
                .unwrap_err();
            assert!(!format!("{error:?}").contains("SECRET"));
        }
        drop(client);
        server.abort();
        let _ = server.await;
    }
}
