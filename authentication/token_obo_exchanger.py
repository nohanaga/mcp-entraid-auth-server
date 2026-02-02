# -*- coding: utf-8 -*-
"""
Token OBO Exchanger
fabric-rti-mcp-mainのtoken_obo_exchanger.pyを参考に実装
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import msal  # type: ignore
from azure.identity import ManagedIdentityCredential

from config.obo_config import OBOFlowEnvVarNames, obo_config

logger = logging.getLogger(__name__)


class TokenOboExchanger:
    """
    On-Behalf-Of (OBO) token exchanger.
    
    ユーザートークンを受け取り、ダウンストリームAPI用のトークンに交換します。
    Managed Identityをクライアント認証情報として使用します。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the TokenOboExchanger with optional configuration.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.tenant_id = obo_config.azure_tenant_id
        self.entra_app_client_id = obo_config.entra_app_client_id
        self.entra_app_client_secret = obo_config.entra_app_client_secret
        self.umi_client_id = obo_config.umi_client_id
        
        logger.info(
            f"TokenOboExchanger initialized with tenant_id: {self.tenant_id}, "
            f"entra_app_client_id: {self.entra_app_client_id}, "
            f"umi_client_id: {self.umi_client_id}, "
            f"using_client_secret: {bool(self.entra_app_client_secret)}"
        )

    async def perform_obo_token_exchange(
        self, user_token: str, resource_uri: str
    ) -> str:
        """
        Perform an On-Behalf-Of token exchange to get a new token for a resource.

        Args:
            user_token: The original user token
            resource_uri: The URI of the target resource to get a token 
                         (ex. https://kusto.kusto.windows.net)

        Returns:
            New access token for the specified resource

        Raises:
            ValueError: If required configuration is missing
            Exception: If token exchange fails
        """
        logger.info(
            f"TokenOboExchanger: Performing OBO token exchange for target resource: {resource_uri}"
        )

        client_id = self.entra_app_client_id

        if not client_id:
            logger.error(
                "TokenOboExchanger: Entra App client ID is not provided for OBO token exchange"
            )
            raise ValueError(
                f"Entra App client ID is required for OBO token exchange. "
                f"Set {OBOFlowEnvVarNames.entra_app_client_id} environment variable."
            )

        if not self.tenant_id:
            logger.error(
                "TokenOboExchanger: Tenant ID not available for OBO token exchange"
            )
            raise ValueError(
                f"{OBOFlowEnvVarNames.azure_tenant_id} environment variable required for OBO token exchange"
            )

        # クライアントシークレットもManaged Identity Client IDもない場合はエラー
        if not self.entra_app_client_secret and not self.umi_client_id:
            logger.error(
                "TokenOboExchanger: Either client secret or UMI Client ID is required"
            )
            raise ValueError(
                f"Either {OBOFlowEnvVarNames.entra_app_client_secret} or "
                f"{OBOFlowEnvVarNames.umi_client_id} environment variable required for OBO token exchange"
            )

        try:
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            
            # クライアント認証情報の準備
            if self.entra_app_client_secret:
                # ローカル開発環境: クライアントシークレットを使用
                logger.info(
                    "TokenOboExchanger: Using Client Secret for OBO token exchange "
                    "(local development mode)"
                )
                client_credential = self.entra_app_client_secret
            else:
                # Azure環境: Managed Identityを使用
                logger.info(
                    f"TokenOboExchanger: Using Managed Identity for OBO token exchange "
                    f"tenant_id: {self.tenant_id}, "
                    f"entra_app_client_id: {self.entra_app_client_id}, "
                    f"umi_client_id: {self.umi_client_id}"
                )

                # Managed Identityでアサーショントークンを取得
                managed_identity_credential = ManagedIdentityCredential(
                    client_id=self.umi_client_id
                )
                mi_scopes = "api://AzureADTokenExchange/.default"
                
                logger.info(
                    f"TokenOboExchanger: Start managed identity token acquire for scopes {mi_scopes}"
                )
                
                access_token_result = managed_identity_credential.get_token(mi_scopes)
                assertion_token = access_token_result.token
                
                client_credential = {
                    "client_assertion": assertion_token,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                }

            # MSALのConfidentialClientApplicationを作成
            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                authority=authority,
                client_credential=client_credential,
            )

            # ターゲットリソースのスコープを設定
            target_scopes = [f"{resource_uri}/.default"]
            logger.info(
                f"TokenOboExchanger: Requesting access to scopes: {target_scopes}"
            )

            # OBOフローでトークンを取得
            result = app.acquire_token_on_behalf_of(
                user_assertion=user_token, scopes=target_scopes
            )

            if "access_token" not in result:
                error_msg = (
                    result.get("error_description")
                    or result.get("error")
                    or "Unknown error"
                )
                error_message = f"TokenOboExchanger: Failed to acquire token: {error_msg}"
                logger.error(error_message)
                raise Exception(error_message)

            logger.info("TokenOboExchanger: Successfully acquired OBO token")
            access_token: str = result["access_token"]
            return access_token
            
        except Exception as e:
            logger.error(f"TokenOboExchanger: Error performing OBO token exchange: {e}")
            raise Exception(f"OBO token exchange failed: {e}") from e
