# HashGate HttpYac Sample

[httpYac](https://httpyac.github.io/) collection demonstrating HMAC authentication with HashGate. Includes public and authenticated endpoint examples.

## Prerequisites

- [httpYac CLI](https://httpyac.github.io/guide/installation_cli) or the [VS Code extension](https://marketplace.visualstudio.com/items?itemName=anweber.vscode-httpyac)
- Node.js (used by the config script to compute HMAC signatures)
- A running HashGate sample server:

```bash
dotnet run --project ../Sample.MinimalApi
```

## Structure

| Folder           | Description                                  |
| ---------------- | -------------------------------------------- |
| `Public/`        | Endpoints that do not require authentication |
| `Authenticated/` | Endpoints secured with HMAC authentication   |

## How It Works

The `httpyac.config.js` file registers a `replaceVariable` hook that intercepts `Authorization` headers matching the pattern:

```
Authorization: HMAC client:{{tokenId}} secret:{{tokenSecret}}
```

The hook automatically computes the HMAC-SHA256 signature and sets the required headers (`host`, `x-timestamp`, `x-content-sha256`, `x-nonce`) on each request.

## Usage

### VS Code Extension

1. Install the **httpYac** VS Code extension
2. Open any `.http` file in this folder
3. Click **Send** above the request

### CLI

```bash
cd samples/Sample.HttpYac
npx httpyac Authenticated/GetUsers.http --env local
```

## Environment Variables

Defined in `httpyac.config.js` under the `local` environment:

| Variable      | Description                          |
| ------------- | ------------------------------------ |
| `host`        | Base URL of the sample API           |
| `tokenId`     | HMAC client identifier               |
| `tokenSecret` | HMAC secret key for signing requests |
