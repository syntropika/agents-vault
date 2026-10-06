# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

The operator interface uses React, TypeScript, Tailwind CSS, and Effect. ESLint, oxfmt, strict type checking, automated interaction checks, and a production build are required verification gates. The existing CLI and service are Rust.

## Users

Developers and operators configuring local credentials for command-line tools and agents. They need to review access before an action uses a credential.

## Product Purpose

Agents Vault provides a local credential broker and the `av` CLI. The operator interface administers credentials and permitted use, with action approval as a separate view.

## Operating Context

The first supported service platforms are Linux and macOS. `av run` can deliver explicitly permitted environment values or route HTTPS through a fixed local proxy. The operator controls storage and policy. Project configuration references credentials rather than containing their values.

## Capabilities and Constraints

SQLCipher is the current credential backend. Native keyring adapters are planned but unimplemented. Credential values must not appear in lists, review payloads, logs, or browser persistence. Permissions remain separate from storage. Approval must show the exact frozen action, target, credential version, duration, and request quota. The implemented MCP adapter requires a compatible MCP Apps harness and fails closed otherwise. An authenticated local console enrolls a harness session once; its App submits exact per-action decisions without a vault password. The configured harness is trusted to enforce App-only tool visibility. Same-user action execution ownership and installed macOS custody remain open security gates. Do not claim production security or untested branded-harness compatibility.

## Brand Commitments

The product name is Agents Vault and the CLI is `av`. Operator UI copy is English. No provider-specific or harness-specific branding or launcher belongs in the generic interface.

The user selected the Focused settings composition: top segmented navigation, a left credential selector, and grouped permission settings on the right. Dark mode is the default, with an optional light theme. The visual language follows shadcn/HeroUI and Apple: rounded controls, compact padding, neutral black/gray/white surfaces, restrained typography, and immediate interaction feedback. This replaces the earlier teal and blue visual proposals.

## Evidence on Hand

Existing Rust storage, broker, CLI, local approval handlers, and synthetic Linux/macOS tests. See `docs/decision-summary.md`, `docs/storage-adapters.md`, and `docs/approval-flow.md`. No customer, benchmark, certification, or production deployment claims are supplied.

## Product Principles

- Local operation without a mandatory cloud service.
- Explicit permission and destination before credential delivery.
- Clear separation between unlock, configuration, and action approval.
- Honest unavailable and error states instead of simulated success.

## Open Decisions

The final web authentication session lifecycle and its integration with future native unlock providers remain engineering choices. The first operator page covers credentials, permissions, and approvals. The user selected an image reference before implementation.

The operator console uses three achromatic near-black/gray background levels, with no pure black: #171717, #212121, and #2f2f2f. Dark remains the default.
