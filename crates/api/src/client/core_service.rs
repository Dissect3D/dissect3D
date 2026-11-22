//! Core-service operations: engine info, credential status and revocation,
//! shutdown and operation reads.

use super::*;

impl Client {
    /// Read actual service capabilities for the discovered engine instance.
    pub async fn info(&self) -> Result<EngineInfo, ClientError> {
        let info: EngineInfo = self.get("/v1/info").await?;
        if info.api_version != API_VERSION
            || !info.required_features.is_empty()
            || info.installation_id != self.installation_id
            || info.instance_id != self.instance_id
        {
            return Err(ClientError::Incompatible);
        }
        Ok(info)
    }

    /// Read this credential's current active status and grants.
    pub async fn auth_status(&self) -> Result<AuthStatus, ClientError> {
        let status: AuthStatus = self.get("/v1/auth/status").await?;
        if status.api_version != API_VERSION
            || status.installation_id != self.installation_id
            || status.instance_id != self.instance_id
            || status.client_id != self.client_id
        {
            return Err(ClientError::Incompatible);
        }
        Ok(status)
    }

    /// Revoke only the credential attached to this client.
    pub async fn revoke_self(&self) -> Result<RevocationReceipt, ClientError> {
        let body = AuthRevokeRequest {
            api_version: API_VERSION.to_owned(),
            required_features: Vec::new(),
        };
        let response = self
            .http
            .post(format!("{}/v1/auth/revoke", self.base_url))
            .header(AUTHORIZATION, self.authorization()?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        let receipt: RevocationReceipt = self.decode_response(response).await?;
        if receipt.api_version != API_VERSION
            || receipt.client_id != self.client_id
            || !receipt.revoked
        {
            return Err(ClientError::Incompatible);
        }
        Ok(receipt)
    }

    /// Ask the discovered instance to stop under one durable idempotency key.
    pub async fn shutdown(&self, key: IdempotencyKey) -> Result<OperationReceipt, ClientError> {
        let body = ShutdownRequest {
            api_version: API_VERSION.to_owned(),
            kind: "engine.shutdown".to_owned(),
            target: OperationTarget {
                kind: "engine".to_owned(),
                instance_id: self.instance_id.clone(),
            },
            options: ShutdownOptions::default(),
            required_features: Vec::new(),
        };
        let response = self
            .http
            .post(format!("{}/v1/operations", self.base_url))
            .header(AUTHORIZATION, self.authorization()?)
            .header("Idempotency-Key", key.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        let receipt: OperationReceipt = self.decode_response(response).await?;
        if receipt.api_version != API_VERSION
            || !receipt.accepted
            || receipt.target.kind != "engine"
            || receipt.target.instance_id != self.instance_id
        {
            return Err(ClientError::Incompatible);
        }
        Ok(receipt)
    }

    /// Read one operation created by this credential.
    pub async fn operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationSnapshot, ClientError> {
        let snapshot: OperationSnapshot = self
            .get(&format!("/v1/operations/{}", operation_id.as_str()))
            .await?;
        if snapshot.api_version != API_VERSION
            || snapshot.operation_id != operation_id
            || snapshot.kind != "engine.shutdown"
        {
            return Err(ClientError::Incompatible);
        }
        Ok(snapshot)
    }
}
