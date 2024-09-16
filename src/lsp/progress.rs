use tokio::sync::mpsc::Sender;
use tower_lsp::{
    lsp_types::{
        notification::Progress, MessageType, NumberOrString, ProgressParams, ProgressParamsValue,
        WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressEnd, WorkDoneProgressReport,
    },
    Client,
};
use tracing::trace;

#[derive(Clone)]
pub(crate) struct ProgressNotifier {
    tx: Sender<ProgressType>,
}

#[derive(Debug)]
pub(crate) enum ProgressType {
    Progress(ProgressNotifierState),
    Notification(NotificationLevel, String),
}

#[derive(Debug)]
pub(crate) enum NotificationLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug)]
pub(crate) enum ProgressNotifierState {
    Start(String, String, Option<String>),
    Update(String, Option<String>, u32),
    Complete(String),
}

impl ProgressNotifier {
    pub fn new(client: tower_lsp::Client) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressType>(32);

        tokio::spawn(async move {
            loop {
                while let Some(progress_type) = rx.recv().await {
                    match progress_type {
                        ProgressType::Progress(progress) => {
                            handle_progress_message(&client, progress).await
                        }
                        ProgressType::Notification(level, message) => {
                            handle_notification(&client, level, message).await
                        }
                    }
                }
            }
        });
        Self { tx }
    }

    pub(crate) async fn send_notification(&self, level: NotificationLevel, message: String) {
        let _ = self
            .tx
            .send(ProgressType::Notification(level, message))
            .await;
    }

    pub(crate) async fn send_progress(&self, progress: ProgressNotifierState) {
        let _ = self.tx.send(ProgressType::Progress(progress)).await;
    }
}

async fn handle_notification(client: &Client, level: NotificationLevel, message: String) {
    let level = match level {
        NotificationLevel::Info => MessageType::INFO,
        NotificationLevel::Warn => MessageType::WARNING,
        NotificationLevel::Error => MessageType::ERROR,
    };
    client.show_message(level, message).await;
}

async fn handle_progress_message(client: &Client, progress: ProgressNotifierState) {
    match progress {
        ProgressNotifierState::Start(token, title, message) => {
            start_progress(client, token, title, message).await
        }
        ProgressNotifierState::Update(token, message, percent) => {
            update(client, token, message, percent).await
        }
        ProgressNotifierState::Complete(token) => done(client, token).await,
    }
}

async fn start_progress(client: &Client, token: String, title: String, message: Option<String>) {
    let wpb = WorkDoneProgressBegin {
        title,
        cancellable: None,
        message,
        percentage: None,
    };
    let token = NumberOrString::String(token);
    let pp = ProgressParams {
        token,
        value: ProgressParamsValue::WorkDone(WorkDoneProgress::Begin(wpb)),
    };
    client.send_notification::<Progress>(pp).await
}

async fn update(client: &Client, token: String, message: Option<String>, percent: u32) {
    let work_done_progress_report = WorkDoneProgressReport {
        cancellable: None,
        message,
        percentage: Some(percent),
    };
    let pp = ProgressParams {
        token: NumberOrString::String(token),
        value: ProgressParamsValue::WorkDone(WorkDoneProgress::Report(work_done_progress_report)),
    };
    client.send_notification::<Progress>(pp).await
}

async fn done(client: &Client, token: String) {
    let wpb = WorkDoneProgressEnd {
        message: Some("complete".to_string()),
    };
    let token = NumberOrString::String(token);
    let pp = ProgressParams {
        token,
        value: ProgressParamsValue::WorkDone(WorkDoneProgress::End(wpb)),
    };
    client.send_notification::<Progress>(pp).await
}
