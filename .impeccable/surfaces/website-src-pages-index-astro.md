---
version: 1
slug: "website-src-pages-index-astro"
primary_target: "website/src/pages/index.astro"
related_targets: ["website/src/styles/landing.css", "website/src/styles/docs.css", "website/src/scripts/landing.ts", "website/src/components/ProjectScene.astro", "website/src/components/FlowScene.astro", "website/src/components/Mark.astro"]
---

# Public website surface

## Scope and mode

Landing: Persuade. Documentation: Read. Developers should understand readable configuration, choose an explicit credential delivery path, and open the CLI quickstart. The public site is independent of the operator console. All shipping prose is English.

## Direction contract

**THESIS:** Readable projects with deliberate access. The project and credential reference provide the first-view mechanism; a separate flow explains reviewed proxy delivery.

**OWN-WORLD:** Three neutral near-black surface tones, pale type, pale action/focus/selection and delivery feedback, flat rounded windows, compact pill controls, Geist sans for headings and prose, and Geist Mono for configuration and code. Inherit [DESIGN.md](../../DESIGN.md), including its website-scoped tokens. The operator console retains its neutral primary roles.

**STORY:** Start with a readable project, understand reviewed delivery, inspect placeholder output and frozen action fields, then use the guides and Markdown exports. The six authored sections cover the configuration-and-release boundary, reviewed delivery, placeholder output, action review, current limits, and documentation exports. Keep current synthetic-credential, custody, and platform limits explicit.

**FIRST VIEWPORT:** A compact 80px header pairs the product name, standalone glyph, and navigation. Pale primary actions use compact 14px type and a 44px minimum height. A large left-aligned two-line headline and compact actions sit beside offset project and credential-reference windows. The project shows real schema-2 syntax with illustrative values and an unresolved credential reference. A configuration-and-release statement closes the first section.

**FORM:** Structural page rails and boundary dividers align the reading grid. Credential-reference details use separated transparent rows within a shared surface. The project window sits in front of the credential-reference window on wide screens. A curved connector relates the reference to project configuration. Lower sections pair explanatory copy with placeholder output or action review fields; the separate delivery scene links command → broker → HTTPS provider. Below the compact breakpoint, windows stack and the delivery flow becomes vertical.

**MOTION:** Connection traces follow a six-second cycle with a delayed outbound trace. Motion runs only for visible scenes in an active document, has an explicit pause control, and becomes static under reduced motion. The environment picker updates public example text and status without accessing a vault.

**TYPE:** Landing and documentation share locally served variable Geist sans and Geist Mono, loaded with `font-display: swap`. The public display uses weight (600), balanced wrapping, and tightened spacing. Configuration and code use Geist Mono; the bundled fonts retain their SIL Open Font License.

**IDENTITY:** A compact closed A/V uses two interlocking filled pieces, a symmetric A roof, triangular negative space, rounded junctions, and matched diagonal angles. `website/public/brand/av-mark.svg` is the canonical neutral tile with dark ink; `website/public/brand/av-symbol.svg` uses the same two glyph paths in pale white. The native SVG assets are font-independent. The landing header and broker use the standalone glyph, while documentation uses the neutral tile. These placements are static; content preparation derives the favicon from the canonical tile.

**ILLUSTRATIONS:** CSS geometry and inline stroke SVG supply the landing scenes.

**FINISH:** Preserve the accepted composition, readable desktop and compact layouts, keyboard focus, working example controls, static reduced-motion behavior, and documented website tokens.

## Constraints

No invented certifications, customer evidence, security claims, or provider-specific coupling. The sample is illustrative and never resolves a credential. Public copy states factual delivery limits without maturity labels. Direct delivery exposes real values; reviewed proxy actions use synthetic credentials; host commands are not confined and a provider can reflect an injected credential. Protected custody and installed-platform acceptance remain under development.

Links, Markdown exports, local search, and documentation appearance controls remain functional. The documentation pipeline and configured publication target retain their established behavior.
