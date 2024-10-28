use async_trait::async_trait;
use crate::domain::{
    email::Email,
    email_client::EmailClient,
};

#[derive(Default, Clone)]
pub struct MockEmailClient;

#[async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        println!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref(),
            subject,
            content
        );
        Ok(())
    }
}