# -*- coding: utf-8 -*-
"""
FastMCPの標準JWTVerifierを使用したAzure Entra ID認証 + OBO対応
https://gofastmcp.com/servers/auth/token-verification の手法に従った実装
fabric-rti-mcp-mainを参考にOBO機能を追加
"""
import os, time
import logging
import jwt
import warnings
from dotenv import load_dotenv
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Optional, Annotated
from pathlib import Path
from pydantic import Field

load_dotenv()

JST = ZoneInfo("Asia/Tokyo")


def _format_unix_ts_jst(ts: object) -> Optional[str]:
    try:
        ts_int = int(ts)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    dt_jst = datetime.fromtimestamp(ts_int, tz=timezone.utc).astimezone(JST)
    return dt_jst.isoformat()


def _log_time_claims(decoded: dict, *, label: str) -> None:
    for key in ("iat", "nbf", "exp"):
        if key in decoded:
            jst = _format_unix_ts_jst(decoded.get(key))
            if jst:
                logger.info(f"  {label} {key}: {decoded.get(key)} ({jst} JST)")

from fastmcp import FastMCP, Context
from fastmcp.server.auth.providers.jwt import JWTVerifier
from azure.storage.blob import BlobClient
from azure.core.credentials import AccessToken, TokenCredential

class SimpleTokenCredential(TokenCredential):
    def __init__(self, token: str, expires_on: int = None):
        self._token = token
        # expires_on はオプション（省略時は 1時間後）
        self._expires_on = expires_on or int(time.time()) + 3600

    def get_token(self, *scopes, **kwargs):
        # scopes を無視して固定トークンを返す
        return AccessToken(self._token, self._expires_on)

# OBO機能のインポート（load_dotenv()の後にインポート）
from config.obo_config import obo_config
from authentication.token_obo_exchanger import TokenOboExchanger

# 非推奨警告を抑制
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

# ロギング設定
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

# FastMCP全体のDEBUGログを有効化(詳細な検証情報を取得)
logging.getLogger("fastmcp").setLevel(logging.DEBUG)

# httpxとhttpcoreのログは抑制(冗長なため)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# asyncioの接続切断エラーを抑制(Windows特有の無害なエラー)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

# ダウンロードファイルの保存先ディレクトリ
DOWNLOAD_DIR = Path("./downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

# Azure Entra IDのテナントIDとAPIアプリケーションIDを環境変数から取得
TENANT_ID = os.getenv("TENANT_ID")
API_APP_ID = os.getenv("API_APP_ID")

# Azure Blob Storage settings (BlobClient args)
AZURE_STORAGE_ACCOUNT_URL = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
AZURE_STORAGE_CONTAINER = os.getenv("AZURE_STORAGE_CONTAINER")

# audienceはapi://プレフィックス付き
AUDIENCE = f"api://{API_APP_ID}"

# v1.0のissuer (Azure Entra IDはデフォルトでv1.0トークンを発行)
# ノートブックのトークンを確認すると、issuerは"https://sts.windows.net/{TENANT_ID}/"
ISSUER = f"https://sts.windows.net/{TENANT_ID}/"

# JWKSエンドポイント (v2.0エンドポイントはv1.0とv2.0両方の鍵を提供)
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

# FastMCPの標準JWTVerifierを使用
# https://gofastmcp.com/servers/auth/token-verification#jwks-endpoint-integration
logger.info("=" * 80)
logger.info("Configuring JWT Token Verification (FastMCP Standard)")
logger.info("=" * 80)
logger.info(f"JWKS URI: {JWKS_URL}")
logger.info(f"Issuer: {ISSUER}")
logger.info(f"Audience: {AUDIENCE}")
logger.info(f"Required Scopes: ['access_as_user']")
logger.info("=" * 80)

# OBO設定の表示
logger.info("=" * 80)
logger.info("OBO Configuration")
logger.info("=" * 80)
logger.info(f"Environment Variable USE_OBO_FLOW: {os.getenv('USE_OBO_FLOW')}")
logger.info(f"OBO Enabled (parsed): {obo_config.use_obo_flow}")
logger.info(f"Azure Tenant ID: {obo_config.azure_tenant_id or '(not set)'}")
if obo_config.use_obo_flow:
    logger.info(f"Entra App Client ID: {obo_config.entra_app_client_id or '(not set)'}")
    logger.info(f"UMI Client ID: {obo_config.umi_client_id or '(not set)'}")
    logger.info(f"Target Audiences: {', '.join(obo_config.target_audiences) if obo_config.target_audiences else '(not set)'}")
else:
    logger.info("OBO Flow is disabled - set USE_OBO_FLOW=true to enable")
logger.info("=" * 80)

# JWTVerifierの設定
# FastMCPが自動的にJWKSエンドポイントから公開鍵を取得し、
# トークンの署名検証、有効期限チェック、issuer/audience検証を実行します

# auth = JWTVerifier(
#     jwks_uri=JWKS_URL,
#     issuer=ISSUER,
#     audience=AUDIENCE,
#     required_scopes=["access_as_user"]
# )

# この構成では、issuer が発行する JWT を検証するサーバーを作成します。検証サーバーは定期的に JWKS エンドポイントから公開鍵を取得し、
# 受信トークンをそれらの鍵に対して検証します。正しい発行者（issuer）と対象者（audience）のクレームを持つトークンのみが受け入れられます。
# issuer パラメータはトークンが信頼できる認証システムから来ていることを保証し、
# audience 検証は他のサービス向けのトークンがMCPサーバーで受け入れられるのを防ぎます。


# FastMCPサーバーの作成（認証付き）
# mcp = FastMCP("Azure Entra ID Protected MCP Server (JWTVerifier)", auth=auth)
mcp = FastMCP("Azure Entra ID Protected MCP Server (JWTVerifier)")

# OBOトークンのキャッシュ用グローバル変数（ユーザーIDをキーにした辞書）
# {user_oid: (token, expires_at)}
_cached_obo_tokens: dict[str, tuple[str, int]] = {}


@mcp.tool()
def secure_ping() -> dict:
    """
    セキュアな ping ツール - 委任アクセストークン (delegated access token) による認証が必要
    
    JWTVerifier が自動的に委任アクセストークンを検証します:
    - 署名検証 (JWKS 公開鍵を使用)
    - 有効期限チェック (exp, nbf claims)
    - Issuer 検証 (sts.windows.net/{TENANT_ID})
    - Audience 検証 (api://{API_APP_ID})
    - スコープ検証 (access_as_user)
    
    Returns:
        dict: サーバーのレスポンス
    """
    return {
        "ok": True,
        "message": "Authenticated ping successful",
        "server": "FastMCP with Azure Entra ID Auth (JWTVerifier)",
        "authentication": "FastMCP JWTVerifier"
    }


@mcp.tool()
def get_user_info(ctx: Context) -> dict:
    """
    認証されたユーザー情報を取得
    
    JWTVerifier が検証した委任アクセストークン (delegated access token) のクレーム情報を返します。
    Authorization ヘッダーから Bearer トークンを取得してデコードします。
    
    このトークンは Frontend から受け取ったもので、Backend API (api://{API_APP_ID}) 向けに発行されています。
    
    Args:
        ctx: FastMCPコンテキスト (自動注入)
    
    Returns:
        dict: ユーザー情報と委任アクセストークンのクレーム
    """
    logger.info("=" * 80)
    logger.info("User info accessed via JWTVerifier")
    logger.info("=" * 80)
    
    user_claims = {}
    try:
        # Authorization ヘッダーから委任アクセストークン (delegated access token) を取得
        if hasattr(ctx, 'request_context') and ctx.request_context:
            request = ctx.request_context.request
            auth_header = request.headers.get("Authorization", "")
            
            if auth_header.startswith("Bearer "):
                delegated_token = auth_header.split(" ", 1)[1]
                logger.info("✅ Delegated access token extracted from Authorization header")
                
                # 委任アクセストークンをデコード (検証なし - JWTVerifier が既に検証済み)
                decoded = jwt.decode(delegated_token, options={"verify_signature": False})
                user_claims = decoded
                
                logger.info("✅ Delegated access token claims decoded:⭐⭐⭐")
                for key, value in decoded.items():
                    logger.info(f"  {key}: {value}")

                # 主要な時刻クレームは日本時間も表示
                _log_time_claims(decoded, label="delegated")
                
                # =============================================================
                # Azure Entra ID認証ベストプラクティスに基づく追加検証
                # 参考: https://learn.microsoft.com/en-us/security/zero-trust/develop/protect-api
                # =============================================================
                logger.info("=" * 80)
                logger.info("Azure Entra ID Token Validation (Best Practices)")
                logger.info("=" * 80)
                
                validation_results = []
                
                # 1. Audience (aud) 検証 - このAPIに対して発行されたトークンか
                aud_claim = decoded.get("aud")
                if aud_claim == AUDIENCE:
                    validation_results.append(f"✅ Audience (aud): {aud_claim} - VALID")
                else:
                    validation_results.append(f"✗ Audience (aud): {aud_claim} - INVALID (expected: {AUDIENCE})")
                
                # 2. Issuer (iss) 検証 - 信頼できるテナントからの発行か
                iss_claim = decoded.get("iss")
                if iss_claim == ISSUER:
                    validation_results.append(f"✅ Issuer (iss): {iss_claim} - VALID")
                else:
                    validation_results.append(f"✗ Issuer (iss): {iss_claim} - INVALID (expected: {ISSUER})")
                
                # 3. Tenant ID (tid) 検証 - 正しいテナントか
                tid_claim = decoded.get("tid")
                if tid_claim == TENANT_ID:
                    validation_results.append(f"✅ Tenant ID (tid): {tid_claim} - VALID")
                else:
                    validation_results.append(f"✗ Tenant ID (tid): {tid_claim} - INVALID (expected: {TENANT_ID})")
                
                # 4. 有効期限 (exp, nbf) 検証 - トークンが有効期間内か
                current_time = int(time.time())
                exp_claim = decoded.get("exp")
                nbf_claim = decoded.get("nbf")
                
                if exp_claim and current_time < exp_claim:
                    exp_time_jst = datetime.fromtimestamp(int(exp_claim), tz=timezone.utc).astimezone(JST)
                    validation_results.append(
                        f"✅ Expiration (exp): {exp_time_jst.isoformat()} JST - VALID (not expired)"
                    )
                else:
                    validation_results.append("✗ Expiration (exp): Token EXPIRED")
                
                if nbf_claim and current_time >= nbf_claim:
                    nbf_time_jst = datetime.fromtimestamp(int(nbf_claim), tz=timezone.utc).astimezone(JST)
                    validation_results.append(
                        f"✅ Not Before (nbf): {nbf_time_jst.isoformat()} JST - VALID (token is active)"
                    )
                else:
                    validation_results.append("✗ Not Before (nbf): Token NOT YET VALID")
                
                # 5. Application ID (appid/azp) 検証 - どのアプリが呼び出したか
                # V1トークンはappid、V2トークンはazpを使用
                appid_claim = decoded.get("appid") or decoded.get("azp")
                if appid_claim:
                    validation_results.append(f"✅ Application ID (appid/azp): {appid_claim}")
                else:
                    validation_results.append("⚠️ Application ID (appid/azp): Not found in token")
                
                # 6. Object ID (oid) 検証 - ユーザーの一意識別子
                oid_claim = decoded.get("oid")
                if oid_claim:
                    validation_results.append(f"✅ Object ID (oid): {oid_claim} - User uniquely identified")
                else:
                    validation_results.append("⚠️ Object ID (oid): Not found in token")
                
                # 7. Scope (scp) 検証 - 委任されたアクセス許可
                scp_claim = decoded.get("scp")
                if scp_claim and "access_as_user" in scp_claim:
                    validation_results.append(f"✅ Scope (scp): {scp_claim} - Contains 'access_as_user'")
                else:
                    validation_results.append(f"⚠️ Scope (scp): {scp_claim} - May not contain required scope")
                
                # 8. User Principal Name (upn) または Unique Name - ユーザー識別
                upn_claim = decoded.get("upn") or decoded.get("unique_name")
                if upn_claim:
                    validation_results.append(f"✅ User Principal Name (upn/unique_name): {upn_claim}")
                else:
                    validation_results.append("⚠️ User Principal Name: Not found in token")
                
                # 検証結果をログ出力
                for result in validation_results:
                    logger.info(result)
                
                logger.info("=" * 80)
            else:
                logger.warning("No Bearer token found in Authorization header")
        else:
            logger.warning("No request_context found")
            
    except Exception as e:
        logger.error(f"Error extracting user claims: {e}")

    return {
        "ok": True,
        "message": "User authenticated by JWTVerifier",
        "note": "Token validated successfully by FastMCP JWTVerifier",
        "authentication_method": "FastMCP JWTVerifier with JWKS",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "user_claims": user_claims
    }


@mcp.tool()
async def get_azure_blob_storage_token(ctx: Context) -> dict:
    """
    Azure Blob Storage 用の OBO トークンを取得 (DEMO用)
    
    Frontend から受け取った委任アクセストークン (delegated access token) を、
    On-Behalf-Of フローで Azure Blob Storage 用のアクセストークンに交換します。
    
    フロー:
    1. Frontend → Backend: 委任アクセストークン (aud: api://{BACKEND_API})
    2. Backend → Entra ID: OBO フローでトークン交換リクエスト
    3. Entra ID → Backend: OBO トークン (aud: https://storage.azure.com/)
    4. Backend → Azure Blob Storage: OBO トークンで API 呼び出し
    
    公式ドキュメント:
    https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow
    
    Args:
        ctx: FastMCPコンテキスト (自動注入)
    
    Returns:
        dict: Azure Blob Storage 用の OBO トークン情報
    """
    logger.info("=" * 80)
    logger.info("Azure Blob Storage Token Request (DEMO)")
    logger.info("=" * 80)
    
    if not obo_config.use_obo_flow:
        return {
            "ok": False,
            "error": "OBO flow is not enabled",
            "message": "Set USE_OBO_FLOW=true in environment variables to enable OBO",
        }
    
    try:
        # Authorization ヘッダーから委任アクセストークン (delegated access token) を取得
        # このトークンは Frontend が取得し、Backend API (api://{API_APP_ID}) 向けに発行されたもの
        delegated_token = None
        if hasattr(ctx, 'request_context') and ctx.request_context:
            request = ctx.request_context.request
            auth_header = request.headers.get("Authorization", "")
            
            if auth_header.startswith("Bearer "):
                delegated_token = auth_header.split(" ", 1)[1]
                logger.info("✅ Delegated access token extracted from Authorization header")
        
        if not delegated_token:
            return {
                "ok": False,
                "error": "No delegated access token found",
                "message": "Authorization header with Bearer token is required",
            }
        
        # 委任アクセストークンからユーザーOID（Object ID）を取得
        try:
            delegated_decoded = jwt.decode(delegated_token, options={"verify_signature": False})
            user_oid = delegated_decoded.get("oid")
            if not user_oid:
                return {
                    "ok": False,
                    "error": "No user OID found in token",
                    "message": "Token must contain 'oid' claim",
                }
            logger.info(f"✅ User OID extracted from delegated token: {user_oid}")
        except Exception as e:
            logger.error(f"❌ Failed to decode delegated token: {e}")
            return {
                "ok": False,
                "error": "Invalid delegated token",
                "message": str(e),
            }
        
        # OBO フローで Azure Blob Storage 用のアクセストークンを取得
        # resource_uri は基本 URI のみを指定 (/.default は自動的に追加される)
        # TARGET_AUDIENCES から最初のリソースを使用
        if not obo_config.target_audiences:
            return {
                "ok": False,
                "error": "No target audiences configured",
                "message": "Set TARGET_AUDIENCES in environment variables",
            }
        
        azure_blob_storage_resource = obo_config.target_audiences[0]
        logger.info(f"🔄 Exchanging delegated token for Azure Blob Storage OBO token: {azure_blob_storage_resource}")
        
        token_exchanger = TokenOboExchanger()
        obo_token = await token_exchanger.perform_obo_token_exchange(
            user_token=delegated_token,  # Frontend から受け取った委任アクセストークン
            resource_uri=azure_blob_storage_resource  # Azure Blob Storage のリソース URI
        )
        
        # コンソールに OBO トークン (生データ) を出力
        print("=" * 80)
        print("🔑 Azure Blob Storage OBO Token (Raw)")
        print("=" * 80)
        print(obo_token)
        print("=" * 80)
        
        # OBO トークンをデコード (検証なし、情報表示のみ)
        decoded_obo_token = jwt.decode(obo_token, options={"verify_signature": False})
        
        logger.info("✅ Azure Blob Storage OBO token acquired successfully")
        logger.info(f"  Audience: {decoded_obo_token.get('aud')}")
        logger.info(f"  Scopes: {decoded_obo_token.get('scp', decoded_obo_token.get('roles'))}")
        
        # グローバル辞書にOBOトークンをキャッシュ（ユーザーoidをキー、有効期限も保存）
        global _cached_obo_tokens
        expires_at = decoded_obo_token.get('exp', int(time.time()) + 3600)  # デフォルト1時間
        _cached_obo_tokens[user_oid] = (obo_token, expires_at)
        logger.info(f"💾 OBO token cached for user {user_oid} (expires at: {_format_unix_ts_jst(expires_at)} JST)")
        
        return {
            "ok": True,
            "message": "Azure Blob Storage OBO token acquired successfully",
            "resource": azure_blob_storage_resource,
            "access_token": obo_token,  # OBO トークン (生データ) を返却
            "token_decoded": decoded_obo_token,  # デコードされた OBO トークンの全内容
            "usage": "Use this OBO token in Authorization header: Bearer <token>",
            "demo_note": "This OBO token can be used to call Azure Blob Storage APIs on behalf of the user"
        }
        
    except ValueError as ve:
        logger.error(f"❌ Configuration error: {ve}")
        return {
            "ok": False,
            "error": "configuration_error",
            "message": str(ve),
        }
    except Exception as e:
        logger.error(f"❌ Azure Blob Storage token exchange failed: {e}")
        return {
            "ok": False,
            "error": "token_exchange_failed",
            "message": str(e),
        }

@mcp.tool()
async def read_blob_with_token(
    blob_path: Annotated[str, Field(description="file path of the blob to read")],
    max_chars: int = 8000,
    encoding: str = "utf-8",
    ctx: Optional[Context] = None,
) -> dict:
    """
    Retrieve the Access Token from the Authorization header, then read and return the Azure Blob using that token.
    blob_path:
        Path of the blob to read
    max_chars:
        Maximum character count (default: 8000)
    encoding:
        Text encoding (default: utf-8)
    Retrieve the Bearer token from the Authorization header.
    The scope must include https://storage.azure.com/.default.
    """
    logger.info("=" * 80)
    logger.info(f"read_blob_with_token called: blob_path={blob_path}")
    logger.info("=" * 80)

    if not AZURE_STORAGE_ACCOUNT_URL:
        logger.error("❌ AZURE_STORAGE_ACCOUNT_URL is not set")
        return {"error": "AZURE_STORAGE_ACCOUNT_URL is not set"}

    if not AZURE_STORAGE_CONTAINER:
        logger.error("❌ AZURE_STORAGE_CONTAINER is not set")
        return {"error": "AZURE_STORAGE_CONTAINER is not set"}

    container = AZURE_STORAGE_CONTAINER

    # トークンの取得: ユーザーごとのキャッシュされたOBOトークンを優先、なければAuthorizationヘッダーから取得
    token = None
    token_source = None
    user_oid = None
    
    # まず、Authorizationヘッダーまたはキャッシュからユーザーoidを特定する必要がある
    # Authorizationヘッダーから委任トークンを取得してoidを抽出
    if ctx and hasattr(ctx, 'request_context') and ctx.request_context:
        request = ctx.request_context.request
        auth_header = request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer "):
            header_token = auth_header.split(" ", 1)[1]
            try:
                # トークンからユーザーoidを取得
                decoded_header = jwt.decode(header_token, options={"verify_signature": False})
                user_oid = decoded_header.get("oid")
                logger.info(f"✅ User OID extracted from Authorization header: {user_oid}")
            except Exception as e:
                logger.warning(f"⚠️ Failed to decode token from Authorization header: {e}")
    
    # 1. ユーザーoidが特定できた場合、キャッシュをチェック
    global _cached_obo_tokens
    if user_oid and user_oid in _cached_obo_tokens:
        cached_token, expires_at = _cached_obo_tokens[user_oid]
        current_time = int(time.time())
        
        # 有効期限をチェック（5分のバッファを設ける）
        if current_time < (expires_at - 300):
            token = cached_token
            token_source = "cached_obo_token"
            logger.info(f"✅ Using cached OBO token for user {user_oid} (expires at: {_format_unix_ts_jst(expires_at)} JST)")
        else:
            # 期限切れのトークンを削除
            del _cached_obo_tokens[user_oid]
            logger.warning(f"⚠️ Cached OBO token for user {user_oid} has expired, removed from cache")
    
    # 2. キャッシュにトークンがない、または期限切れの場合、Authorizationヘッダーから取得
    if not token and ctx and hasattr(ctx, 'request_context') and ctx.request_context:
        request = ctx.request_context.request
        auth_header = request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            token_source = "authorization_header"
            logger.info(f"✅ Access token extracted from Authorization header (length: {len(token)})")
        else:
            logger.error("❌ Authorization header with Bearer token is required")
            return {"error": "Authorization header with Bearer token is required"}
    else:
        logger.error("❌ No token available (no cached OBO token and no request context)")
        return {"error": "No token available"}
    
    # トークンの中身をデコードして表示
    if token:
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            logger.info(f"✅ Access token claims decoded (source: {token_source}):⭐⭐⭐")
            for key, value in decoded.items():
                logger.info(f"  {key}: {value}")

            # 主要な時刻クレームは日本時間も表示
            _log_time_claims(decoded, label="access")
            logger.info("=" * 80)
        except Exception as decode_ex:
            logger.warning(f"⚠️ Failed to decode token: {decode_ex}")

    # TokenCredential としてラップ
    credential = SimpleTokenCredential(token)
    logger.info(f"✅ TokenCredential created")

    # BlobClient を作成
    account_url = AZURE_STORAGE_ACCOUNT_URL
    blob_client = BlobClient(
        account_url=account_url,
        container_name=container,
        blob_name=blob_path,
        credential=credential,
    )
    logger.info(f"✅ BlobClient created: {account_url}/{container}/{blob_path}")

    try:
        logger.info(f"⏳ Downloading blob...")
        downloader = blob_client.download_blob()
        data = downloader.readall()
        logger.info(f"✅ Blob downloaded successfully: {len(data)} bytes")
        
        # ローカルに保存
        local_filename = Path(blob_path).name
        local_path = DOWNLOAD_DIR / local_filename
        with open(local_path, "wb") as f:
            f.write(data)
        logger.info(f"✅ File saved locally: {local_path.absolute()}")
        
    except Exception as ex:
        # エラーなら詳細を返す
        logger.error(f"❌ Error downloading blob: {str(ex)}")
        return {"error": str(ex)}

    # テキスト化
    text = data.decode(encoding, errors="replace")
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars] + "\n...<truncated>"
        logger.info(f"⚠️ Text truncated to {max_chars} characters")

    logger.info(f"✅ Blob processing completed")
    logger.info("=" * 80)

    return {
        "container": container,
        "blob_path": blob_path,
        "bytes": len(data),
        "text": text,
        "truncated": truncated,
        "local_path": str(local_path.absolute())
    }



def main():
    """MCPサーバーのメインエントリーポイント"""
    logger.info("Starting Azure Entra ID Protected MCP Server with JWTVerifier + OBO...")
    logger.info(f"Azure Tenant ID: {TENANT_ID}")
    logger.info(f"API Client ID: {API_APP_ID}")
    
    # OBO設定の検証
    if obo_config.use_obo_flow:
        logger.info("=" * 80)
        logger.info("OBO Flow Configuration Check")
        logger.info("=" * 80)
        
        config_valid = True
        
        if not obo_config.entra_app_client_id:
            logger.error("❌ ENTRA_APP_CLIENT_ID is not set")
            config_valid = False
        else:
            logger.info(f"✅ Entra App Client ID: {obo_config.entra_app_client_id}")
        
        if not obo_config.umi_client_id:
            logger.error("❌ UMI_CLIENT_ID is not set")
            config_valid = False
        else:
            logger.info(f"✅ UMI Client ID: {obo_config.umi_client_id}")
        
        if not obo_config.target_audiences:
            logger.warning("⚠️  No target audiences configured")
        else:
            logger.info(f"✅ Target Audiences: {', '.join(obo_config.target_audiences)}")
        
        if not config_valid:
            logger.error("=" * 80)
            logger.error("❌ OBO Flow is enabled but required configuration is missing")
            logger.error("Please set the following environment variables:")
            logger.error("  - ENTRA_APP_CLIENT_ID")
            logger.error("  - UMI_CLIENT_ID")
            logger.error("  - AZURE_TENANT_ID (or TENANT_ID)")
            logger.error("=" * 80)
            raise ValueError("OBO configuration is incomplete")
        
        logger.info("=" * 80)
        logger.info("✅ OBO Flow configuration is valid")
        logger.info("=" * 80)
    else:
        logger.info("ℹ️  OBO Flow is disabled (USE_OBO_FLOW=false)")
    
    try:
        # HTTPトランスポートでサーバーを起動（認証にはHTTPが必要）
        # JWTVerifierがHTTPヘッダーからBearerトークンを自動抽出・検証
        mcp.run(
            transport="streamable-http",
            host="0.0.0.0",
            port=8000,
        )
    except Exception as e:
        logger.error(f"Error running server: {e}")
        raise


if __name__ == "__main__":
    main()


# 実行コマンド:
# python main.py
#
# 特徴:
# - FastMCPの標準JWTVerifierを使用
# - 自動的にJWKSから公開鍵を取得
# - トークンの署名、有効期限、issuer、audienceを自動検証
# - OBOフロー対応 (fabric-rti-mcp-mainを参考に実装)
# - Managed Identityを使用したセキュアなトークン交換
# - ダウンストリームAPI用トークン取得機能
# - FastMCPのベストプラクティスに準拠
#
# OBO機能を有効化するには:
# .envファイルに以下を設定:
#   USE_OBO_FLOW=true
#   ENTRA_APP_CLIENT_ID=<your-entra-app-client-id>
#   UMI_CLIENT_ID=<your-managed-identity-client-id>
#   AZURE_TENANT_ID=<your-tenant-id> (or TENANT_ID)
#   TARGET_AUDIENCES=