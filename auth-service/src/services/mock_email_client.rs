use async_trait::async_trait;
use color_eyre::eyre::{eyre, Result};
use crate::domain::{
    email::Email,
    email_client::EmailClient,
};

#[derive(Default, Clone)]
pub struct MockEmailClient;

#[async_trait]
impl EmailClient for MockEmailClient {
    #[tracing::instrument(name = "Sending mock email", skip(self, content))]
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()> {
        tracing::debug!(
            recipient = %recipient,
            subject = %subject,
            "Sending mock email"
        );
        Ok(())
    }
}
