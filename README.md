# MCP Entra ID Auth Server

Microsoft Entra ID (旧 Azure AD) 認証を使用した Model Context Protocol (MCP) サーバーのサンプル実装です。FastMCP を使用した認証付き MCP サーバーで、On-Behalf-Of (OBO) フローによる Azure Blob Storage などのダウンストリーム API へのアクセスをサポートします。

## 📋 目次

- [概要](#概要)
- [アーキテクチャ](#アーキテクチャ)
- [主な機能](#主な機能)
- [前提条件](#前提条件)
- [セットアップ](#セットアップ)
- [使用方法](#使用方法)
- [環境変数](#環境変数)
- [OBO フロー](#obo-フロー)
- [セキュリティ](#セキュリティ)
- [トラブルシューティング](#トラブルシューティング)

## 概要

このプロジェクトは、Microsoft Entra ID を使用した安全な認証フローと、FastMCP を使用した Model Context Protocol サーバーの実装例を提供します。JWTVerifier による委任アクセストークンの検証、OBO フローによるトークン交換、Azure Blob Storage へのアクセス機能を備えています。

### 認証フロー

```
Client → MCP Server (FastMCP) → Downstream API (Azure Blob Storage等)
         |                              |
         └→ JWT Verification           └→ OBO Token Exchange
```

## アーキテクチャ

### MCP Server (FastMCP)
- **認証**: JWTVerifier による委任アクセストークンの検証
- **トークン検証**: JWKS エンドポイントから公開鍵を取得し、自動検証
- **OBO フロー**: Managed Identity を使用したセキュアなトークン交換
- **ツール**: 
  - `secure_ping`: 認証確認用ツール
  - `get_user_info`: ユーザー情報とトークンクレームの取得
  - `get_azure_blob_storage_token`: Azure Blob Storage 用 OBO トークン取得
  - `read_blob_with_token`: Azure Blob Storage からのファイル読み込み

## 主な機能

### ✅ 認証・認可
- Microsoft Entra ID による OAuth 2.0 / OpenID Connect 認証
- JWT トークンの自動検証（署名、有効期限、issuer、audience）
- JWKS エンドポイントから公開鍵を自動取得
- スコープベースのアクセス制御（`access_as_user` スコープ必須）
- テナント ID、Application ID、Object ID の検証

### ✅ On-Behalf-Of (OBO) フロー
- ダウンストリーム API 用のトークン交換
- Managed Identity によるセキュアな認証
- クライアントシークレット対応（ローカル開発用）
- 複数のリソース URI サポート（カンマ区切りで指定可能）

### ✅ Azure Blob Storage アクセス
- OBO トークンを使用した Azure Blob Storage へのアクセス
- テキストファイルの読み込みとローカル保存
- 自動的にトークンの有効期限を管理

### ✅ MCP ツール
- **secure_ping**: 認証が必要なセキュアな ping ツール
- **get_user_info**: 認証されたユーザー情報とトークンクレームの取得
- **get_azure_blob_storage_token**: Azure Blob Storage 用 OBO トークン取得（デモ用）
- **read_blob_with_token**: Azure Blob Storage からのファイル読み込み

## 前提条件

- Python 3.10 以上
- Microsoft Entra ID テナント
- Azure Blob Storage（Blob 読み込み機能を使用する場合）
- Azure Managed Identity（OBO フロー使用時、Azure 環境のみ）

## セットアップ

### 1. リポジトリのクローン

```bash
git clone https://github.com/nohanaga/mcp-entraid-auth-server
cd mcp-entraid-auth-server
```

### 2. Entra ID アプリ登録（OAuth ID パススルー）

#### MCP Server API アプリの登録

1. Azure Portal で「アプリの登録」を開く
2. 新しいアプリを登録（例: `MCP-Server-API`）
3. 「API の公開」で以下を設定:
   - アプリケーション ID URI: `api://<CLIENT_ID>`
   - スコープを追加: `access_as_user`
     - スコープ名: `access_as_user`
     - 同意できるのは: 管理者とユーザー
     - 管理者の同意の表示名: `Access MCP Server as user`
     - 管理者の同意の説明: `Allow the application to access MCP Server on behalf of the signed-in user`
     - ユーザーの同意の表示名: `Access MCP Server as you`
     - ユーザーの同意の説明: `Allow the application to access MCP Server on your behalf`
     - 状態: 有効
   - 「<テナント名> に管理者の同意を与えます」ボタンをクリック
4. クライアント ID をメモ（`API_APP_ID`）

#### OBO フローを使用する場合の追加設定

1. 「証明書とシークレット」でクライアントシークレットを作成（ローカル開発用）
2. 「API のアクセス許可」で以下を追加:
   - Azure Storage: `user_impersonation`（委任）
   - 「<テナント名> に管理者の同意を与えます」ボタンをクリック
3. Azure 環境の場合は Managed Identity を設定し、Federated Credentials を構成

### 3. 依存関係のインストール

```bash
pip install -r requirements.txt
```

### 4. 環境変数の設定

`.env` ファイルを作成し、以下の値を設定します:

```env
# Entra ID 設定
TENANT_ID="your-tenant-id-here"
API_APP_ID="your-api-app-id-here"

# Azure Blob Storage 設定（オプション - Blob 読み込み機能を使用する場合）
AZURE_STORAGE_ACCOUNT_URL="https://your-storage-account.blob.core.windows.net"
AZURE_STORAGE_CONTAINER="your-container-name"

# OBO フロー設定（オプション）
USE_OBO_FLOW=false
AZURE_TENANT_ID="your-tenant-id-here"
ENTRA_APP_CLIENT_ID="your-api-app-id-here"
ENTRA_APP_CLIENT_SECRET="your-client-secret-here"  # ローカル開発のみ
UMI_CLIENT_ID="your-managed-identity-client-id"  # Azure 環境のみ
TARGET_AUDIENCES="https://storage.azure.com"  # カンマ区切りで複数指定可能
```

## 使用方法

### 1. MCP サーバーの起動

```bash
python main.py
```

サーバーは `http://localhost:8000` で起動します。

### 2. MCP クライアントからの接続

MCP クライアントから、以下の設定で接続します:

- **URL**: `http://localhost:8000/mcp`
- **認証**: Bearer トークン
- **スコープ**: `api://{API_APP_ID}/access_as_user` や `https://storage.azure.com`

### 3. 利用可能なツール

#### `secure_ping`
認証確認用のシンプルなツールです。認証が成功していることを確認できます。

```json
{
  "ok": true,
  "message": "Authenticated ping successful",
  "server": "FastMCP with Azure Entra ID Auth (JWTVerifier)",
  "authentication": "FastMCP JWTVerifier"
}
```

#### `get_user_info`
認証されたユーザー情報とトークンクレームを取得します。

返却される情報:
- ユーザーの Object ID (oid)
- ユーザー Principal Name (upn)
- Application ID (appid)
- テナント ID (tid)
- スコープ (scp)
- トークンの有効期限 (exp, nbf, iat)
- その他のトークンクレーム

#### `get_azure_blob_storage_token`
Azure Blob Storage 用の OBO トークンを取得します（デモ用）。

返却される情報:
- OBO トークン（生データ）
- デコードされたトークン情報
- 使用方法の説明

#### `read_blob_with_token`
Azure Blob Storage からファイルを読み込みます。

パラメータ:
- `blob_path`: 読み込むファイルのパス
- `max_chars`: 最大文字数（デフォルト: 8000）
- `encoding`: エンコーディング（デフォルト: utf-8）

返却される情報:
- コンテナ名
- Blob パス
- ファイルサイズ（バイト）
- ファイル内容（テキスト）
- ローカル保存パス

### 4. OBO トークンの取得とテスト

OBO フローを有効化している場合、以下の手順でテストできます:

1. `get_azure_blob_storage_token` ツールを呼び出す
2. 返却された OBO トークンをコピー
3. `read_blob_with_token` ツールで Azure Blob Storage にアクセス

### 5. ログの確認

サーバーは詳細なログを出力します:
- トークンの検証結果
- OBO フローの実行状況
- Azure Blob Storage へのアクセス状況
- エラー情報
## 環境変数

### 必須の環境変数

| 変数名 | 説明 | 例 |
|--------|------|-----|
| `TENANT_ID` | Azure Entra ID テナント ID | `12345678-1234-1234-1234-123456789abc` |
| `API_APP_ID` | MCP Server API のアプリケーション ID | `87654321-4321-4321-4321-cba987654321` |

### Azure Blob Storage 関連（オプション）

| 変数名 | 説明 | 例 |
|--------|------|-----|
| `AZURE_STORAGE_ACCOUNT_URL` | Azure Storage アカウントの URL | `https://mystorageaccount.blob.core.windows.net` |
| `AZURE_STORAGE_CONTAINER` | コンテナ名 | `mycontainer` |

### OBO フロー関連（オプション）

| 変数名 | 説明 | 例 |
|--------|------|-----|
| `USE_OBO_FLOW` | OBO フローの有効化（true/false） | `true` |
| `AZURE_TENANT_ID` | Azure テナント ID（TENANT_ID と同じ値でも可） | `12345678-1234-1234-1234-123456789abc` |
| `ENTRA_APP_CLIENT_ID` | Entra アプリのクライアント ID | `87654321-4321-4321-4321-cba987654321` |
| `ENTRA_APP_CLIENT_SECRET` | クライアントシークレット（ローカル開発用） | `your-secret-here` |
| `UMI_CLIENT_ID` | Managed Identity のクライアント ID（Azure 環境用） | `11111111-1111-1111-1111-111111111111` |
| `TARGET_AUDIENCES` | ターゲットリソースの URI（カンマ区切り） | `https://storage.azure.com` |

### On-Behalf-Of (OBO) フローとは

OBO フローは、ユーザーの委任されたアクセス許可を使用して、ダウンストリーム API にアクセスするための OAuth 2.0 フローです。

### フロー図

```
1. ユーザー認証（クライアント側で実施）
   User → Client: ログイン
   Client → Entra ID: 認証リクエスト
   Entra ID → Client: アクセストークン

2. 委任アクセストークンの取得（クライアント側で実施）
   Client → Entra ID: トークンリクエスト (MCP Server API用スコープ)
   Entra ID → Client: 委任アクセストークン (aud: api://{API_APP_ID})

3. MCP Server へのリクエスト
   Client → MCP Server: 委任アクセストークン (Authorization ヘッダー)
   MCP Server: JWT 検証 (JWTVerifier)

4. OBO トークン交換
   MCP Server → Entra ID: OBO リクエスト + Managed Identity
   Entra ID → MCP Server: OBO トークン (aud: https://storage.azure.com)

5. リソースアクセス
   MCP Server → Azure Blob Storage: OBO トークン
   Azure Blob Storage → MCP Server: データ
   MCP Server → Client: レスポンス
```

### OBO フローの有効化

1. `.env` ファイルで `USE_OBO_FLOW=true` に設定
2. 必要な環境変数を設定（上記参照）
3. Azure 環境の場合、Managed Identity を設定
4. Entra ID アプリで Federated Credentials を設定

### サポートされるリソース

デフォルトで以下のリソースに対応:

- Azure Blob Storage: `https://storage.azure.com`

`TARGET_AUDIENCES` 環境変数で追加のリソースを指定できます（カンマ区切り）。

## セキュリティ

### 実装されているセキュリティ機能

- ✅ JWT トークンの署名検証（JWKS による公開鍵検証）
- ✅ トークンの有効期限チェック（exp, nbf クレーム）
- ✅ Issuer 検証（信頼できるテナントからの発行）
- ✅ Audience 検証（正しい API 向けのトークン）
- ✅ Tenant ID 検証（正しいテナントからのアクセス）
- ✅ Application ID (appid/azp) 検証
- ✅ Object ID (oid) 検証（ユーザーの一意識別）
- ✅ スコープベースのアクセス制御（access_as_user）
- ✅ User Principal Name (upn) 検証
- ✅ HTTPS 推奨（本番環境）

### トークン検証の詳細

サーバーは以下の検証を自動的に実行します:

1. **署名検証**: JWKS エンドポイントから取得した公開鍵でトークン署名を検証
2. **有効期限検証**: `exp` クレームでトークンの有効期限を確認
3. **使用開始時刻検証**: `nbf` クレームでトークンが有効になる時刻を確認
4. **Issuer 検証**: `iss` クレームが `https://sts.windows.net/{TENANT_ID}/` であることを確認
5. **Audience 検証**: `aud` クレームが `api://{API_APP_ID}` であることを確認
6. **テナント検証**: `tid` クレームが期待されるテナント ID であることを確認
7. **スコープ検証**: `scp` クレームに `access_as_user` が含まれることを確認

### セキュリティベストプラクティス

1. **本番環境では必ず HTTPS を使用**
2. **クライアントシークレットは環境変数で管理**（Git にコミットしない）
3. **Managed Identity を使用**（Azure 環境）
4. **トークンの有効期限を適切に設定**
5. **最小権限の原則に従う**
6. **定期的なセキュリティ監査**
7. **ログの監視と異常検知**
8. **OBO フローの適切な設定**（Federated Credentials の使用）

### 参考リソース

- [Microsoft Entra ID ベストプラクティス](https://learn.microsoft.com/ja-jp/security/zero-trust/develop/protect-api)
- [OAuth 2.0 OBO フロー](https://learn.microsoft.com/ja-jp/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [JWT トークン検証](https://learn.microsoft.com/ja-jp/entra/identity-platform/access-tokens)

## トラブルシューティング

### よくある問題

#### 1. `AADSTS65001: The user or administrator has not consented`

**原因**: API のアクセス許可に同意していない

**解決方法**:
1. Azure Portal で MCP Server API アプリの「API のアクセス許可」を開く
2. 「<テナント名> に管理者の同意を与えます」をクリック

#### 2. `Audience validation failed`

**原因**: トークンの audience が正しくない

**解決方法**:
- `.env` ファイルの `API_APP_ID` が正しいか確認
- クライアント側でトークンを取得する際のスコープが `api://{API_APP_ID}/access_as_user` になっているか確認
- Entra ID アプリの「API の公開」で ID URI が `api://{CLIENT_ID}` になっているか確認

#### 3. `Issuer validation failed`

**原因**: トークンの issuer が期待値と一致しない

**解決方法**:
- `TENANT_ID` が正しいか確認
- V1 トークンを使用していることを確認（issuer: `https://sts.windows.net/{TENANT_ID}/`）
- V2 トークンを使用する場合は、issuer の設定を変更

#### 4. OBO トークン交換が失敗する

**原因**: OBO 設定が不完全、または Federated Credentials が未設定

**解決方法**:
- 全ての OBO 関連環境変数が設定されているか確認
- Managed Identity が正しく設定されているか確認（Azure 環境の場合）
- クライアントシークレットが正しく設定されているか確認（ローカル開発の場合）
- Entra ID アプリで Federated Credentials が設定されているか確認
- API のアクセス許可で Azure Storage の `user_impersonation` に同意しているか確認

#### 5. `read_blob_with_token` でエラーが発生する

**原因**: OBO トークンが Azure Blob Storage 用に正しく発行されていない、または Blob が存在しない

**解決方法**:
- `get_azure_blob_storage_token` で取得したトークンの audience が `https://storage.azure.com` であることを確認
- `AZURE_STORAGE_ACCOUNT_URL` と `AZURE_STORAGE_CONTAINER` が正しく設定されているか確認
- 指定した Blob パスが正しく、Blob が存在するか確認
- Azure Storage アカウントのアクセス権限を確認

#### 6. `No Bearer token found in Authorization header`

**原因**: Authorization ヘッダーが設定されていない、または形式が正しくない

**解決方法**:
- MCP クライアントから `Authorization: Bearer <token>` ヘッダーを送信しているか確認
- トークンが正しく取得できているか確認
- トークンの有効期限が切れていないか確認

#### 7. ログに `Windows Proactor Event Loop` のエラーが表示される

**原因**: Windows 環境での asyncio の既知の無害なエラー

**解決方法**:
- このエラーは無視しても問題ありません
- `logging.getLogger("asyncio").setLevel(logging.CRITICAL)` が設定されているため、通常は表示されません

## ライセンス

MIT License

このプロジェクトは、サンプルコードとして提供されています。

## 参考資料

- [FastMCP Documentation](https://gofastmcp.com/)
- [FastMCP Authentication - Token Verification](https://gofastmcp.com/servers/auth/token-verification)
- [Microsoft identity platform](https://learn.microsoft.com/ja-jp/entra/identity-platform/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Azure Entra ID - Protect an API](https://learn.microsoft.com/ja-jp/security/zero-trust/develop/protect-api)
- [OAuth 2.0 On-Behalf-Of Flow](https://learn.microsoft.com/ja-jp/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [Azure Blob Storage Python SDK](https://learn.microsoft.com/ja-jp/python/api/overview/azure/storage-blob-readme)
