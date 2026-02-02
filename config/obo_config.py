# -*- coding: utf-8 -*-
"""
OBO (On-Behalf-Of) Flow Configuration
fabric-rti-mcp-mainを参考に実装
"""
import os
from dataclasses import dataclass
from typing import List


class OBOFlowEnvVarNames:
    """Environment variable names for OBO Flow configuration."""

    azure_tenant_id = "AZURE_TENANT_ID"
    # client id for the Entra App which is used to authenticate the user
    entra_app_client_id = "ENTRA_APP_CLIENT_ID"
    # client secret for the Entra App (for local development)
    entra_app_client_secret = "ENTRA_APP_CLIENT_SECRET"
    # user assigned managed identity client id used as Federated credentials on the Entra App
    umi_client_id = "UMI_CLIENT_ID"
    # Target resource audiences (comma-separated)
    target_audiences = "TARGET_AUDIENCES"
    # Enable/disable OBO flow
    use_obo_flow = "USE_OBO_FLOW"


# Default values for OBO Flow configuration
DEFAULT_AZURE_TENANT_ID = ""
DEFAULT_ENTRA_APP_CLIENT_ID = ""
DEFAULT_ENTRA_APP_CLIENT_SECRET = ""
DEFAULT_UMI_CLIENT_ID = ""
DEFAULT_TARGET_AUDIENCES = "https://kusto.kusto.windows.net,https://analysis.windows.net/powerbi/api"
DEFAULT_USE_OBO_FLOW = False


@dataclass(slots=True, frozen=True)
class OBOFlowAuthConfig:
    """Configuration for OBO (On-Behalf-Of) Flow authentication."""

    azure_tenant_id: str
    entra_app_client_id: str
    entra_app_client_secret: str
    umi_client_id: str
    target_audiences: List[str]
    use_obo_flow: bool

    @staticmethod
    def from_env() -> "OBOFlowAuthConfig":
        """Load OBO Flow configuration from environment variables."""
        target_audiences_str = os.getenv(
            OBOFlowEnvVarNames.target_audiences, DEFAULT_TARGET_AUDIENCES
        )
        target_audiences = [
            aud.strip() for aud in target_audiences_str.split(",") if aud.strip()
        ]
        
        use_obo_flow_str = os.getenv(
            OBOFlowEnvVarNames.use_obo_flow, str(DEFAULT_USE_OBO_FLOW)
        )
        use_obo_flow = use_obo_flow_str.lower() in ("true", "1", "yes")

        return OBOFlowAuthConfig(
            azure_tenant_id=os.getenv(
                OBOFlowEnvVarNames.azure_tenant_id, DEFAULT_AZURE_TENANT_ID
            ),
            entra_app_client_id=os.getenv(
                OBOFlowEnvVarNames.entra_app_client_id, DEFAULT_ENTRA_APP_CLIENT_ID
            ),
            entra_app_client_secret=os.getenv(
                OBOFlowEnvVarNames.entra_app_client_secret, DEFAULT_ENTRA_APP_CLIENT_SECRET
            ),
            umi_client_id=os.getenv(
                OBOFlowEnvVarNames.umi_client_id, DEFAULT_UMI_CLIENT_ID
            ),
            target_audiences=target_audiences,
            use_obo_flow=use_obo_flow,
        )

    @staticmethod
    def existing_env_vars() -> List[str]:
        """Return a list of environment variable names that are currently set."""
        result: List[str] = []
        env_vars = [
            OBOFlowEnvVarNames.azure_tenant_id,
            OBOFlowEnvVarNames.entra_app_client_id,
            OBOFlowEnvVarNames.entra_app_client_secret,
            OBOFlowEnvVarNames.umi_client_id,
            OBOFlowEnvVarNames.target_audiences,
            OBOFlowEnvVarNames.use_obo_flow,
        ]
        for env_var in env_vars:
            if os.getenv(env_var) is not None:
                result.append(env_var)
        return result


# Global OBO configuration instance
obo_config = OBOFlowAuthConfig.from_env()
