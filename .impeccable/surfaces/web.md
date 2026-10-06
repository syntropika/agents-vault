---
version: 1
slug: "web"
primary_target: "web"
related_targets: []
---

# Operator console

Mode: Operate. Scope: local credential administration, permissions, and separate task approval. React, Tailwind, Effect, strict verification.

## Direction contract

THESIS: A focused settings console keeps the selected credential and its permitted use visible together.
OWN-WORLD: Three achromatic surface levels (#171717, #212121, #2f2f2f), white primary action, rounded compact shadcn/HeroUI controls, Apple system typography; optional light theme.
STORY: Authenticate locally, select or add a credential, inspect the exact host and access policy, and review pending tasks separately. Secret values never appear in lists.
FIRST VIEWPORT: Centered shell, top segmented navigation, page heading and Add credential action, a left searchable credential selector, and grouped label/value permission rows on the right. The selected light reference establishes composition; the user's later dark-mode and compact rounded-control instructions override its palette and control dimensions.
FORM: User-selected Focused settings (layout 3), seed d28fb5d8. Approved reference: /home/cerberus/.codex/artifacts/research/av-web-20261006/rounded-settings.png. Signature interaction: immediate selection feedback and inline editor expansion; reduced motion retains static feedback.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

No shipping raster is required: all product content, controls, and icons are semantic UI. Temporary references and verification captures stay outside the repository according to the user's artifact instructions.

Palette refinement: the user clarified that all three main backgrounds should be near-black or gray, with no pure black and no blue/violet cast. The darkest level (#171717) is the main background and shell. Panels and the selector use #212121; control tracks, fields, selected rows, and small tiles use #2f2f2f.
