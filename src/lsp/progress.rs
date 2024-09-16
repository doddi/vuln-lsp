use tokio::sync::mpsc::Sender;
use tower_lsp::{
    lsp_types::{
        notification::Progress, NumberOrString, ProgressParams, ProgressParamsValue,
        WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressEnd, WorkDoneProgressReport,
    },
    Client,
};

#[derive(Clone)]
pub(crate) struct ProgressNotifier {
    tx: Sender<ProgressNotifierState>,
}

pub(crate) enum ProgressNotifierState {
    Start(String, String, Option<String>),
    Update(String, Option<String>, u32),
    Complete(String),
}

impl ProgressNotifier {
    pub fn new(client: tower_lsp::Client) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressNotifierState>(1);

        tokio::spawn(async move {
            loop {
                while let Some(progress) = rx.recv().await {
                    handle_message(&client, progress).await;
                }
            }
        });
        Self { tx }
    }

    pub(crate) async fn send(&self, progress: ProgressNotifierState) {
        let _ = self.tx.send(progress).await;
    }
}

async fn handle_message(client: &Client, progress: ProgressNotifierState) {
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
