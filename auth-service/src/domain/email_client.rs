use async_trait::async_trait;
use color_eyre::eyre::Result;
use super::email::Email;

#[async_trait]
pub trait EmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()>;
}