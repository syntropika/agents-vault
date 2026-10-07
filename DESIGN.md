---
name: Agents Vault
description: Restrained credential administration and a public guide to readable configuration and explicit access.
colors:
  bg: "#171717"
  surface: "#212121"
  panel: "#212121"
  subtle: "#2f2f2f"
  hover: "#2f2f2f"
  border: "#404040"
  text: "#ececec"
  muted: "#b5b5b5"
  primary: "#ececec"
  primary-ink: "#212121"
  light-bg: "#f5f5f7"
  light-surface: "#fff"
  light-panel: "#fafafa"
  light-subtle: "#f0f0f2"
  light-hover: "#e7e7eb"
  light-border: "#dedee3"
  light-text: "#1c1c20"
  light-muted: "#62626d"
  light-primary: "#18181b"
  light-primary-ink: "#fff"
  website-divider: "#303030"
  website-accent: "#c4a7ff"
  website-accent-hover: "#d6c2ff"
  website-accent-surface: "#2e253e"
  website-accent-ink: "#241735"
  website-light-accent: "#65419a"
  website-light-accent-low: "#f1e9ff"
  website-light-accent-high: "#442467"
typography:
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "30px"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  detail-title:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "24px"
    fontWeight: 650
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: 1.5
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  control:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "13px"
    fontWeight: 550
    lineHeight: 1.5
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "12px"
    fontWeight: 550
    lineHeight: 1.5
  caption:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "11px"
    fontWeight: 400
    lineHeight: 1.5
  website-display:
    fontFamily: "Geist, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "clamp(42px, 5vw, 76px)"
    fontWeight: 600
    lineHeight: 1.07
    letterSpacing: "-0.04em"
  website-headline:
    fontFamily: "Geist, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "42px"
    fontWeight: 650
    lineHeight: 1.15
    letterSpacing: "-0.035em"
  website-body:
    fontFamily: "Geist, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.8
  website-action:
    fontFamily: "Geist, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "18px"
    fontWeight: 600
  website-code:
    fontFamily: "Geist Mono, ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "25px"
rounded:
  badge: "8px"
  field: "12px"
  row: "14px"
  group: "18px"
  panel: "20px"
  shell: "24px"
  pill: "999px"
  website-window: "16px"
  website-project-window: "14px"
spacing:
  tight: "4px"
  icon: "8px"
  control-gap: "10px"
  compact: "12px"
  regular: "16px"
  section: "20px"
  action: "22px"
  panel: "24px"
  stage: "32px"
  website-section: "100px"
  website-section-compact: "60px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.control}"
    rounded: "{rounded.pill}"
    padding: "8px 16px"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    typography: "{typography.control}"
    rounded: "{rounded.pill}"
    padding: "8px 16px"
  button-secondary-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.text}"
  button-text:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "0"
    padding: "6px 3px"
  button-icon:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "50%"
    size: "32px"
  field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.field}"
    padding: "10px 12px"
    width: "100%"
  navigation:
    backgroundColor: "{colors.subtle}"
    rounded: "{rounded.pill}"
    padding: "4px"
  badge:
    backgroundColor: "{colors.subtle}"
    textColor: "{colors.muted}"
    rounded: "{rounded.badge}"
    padding: "3px 8px"
  settings-group:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.group}"
  credential-row-selected:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.text}"
    rounded: "{rounded.row}"
    padding: "12px 9px"
  website-brand-mark:
    backgroundColor: "{colors.website-accent}"
    textColor: "{colors.website-accent-ink}"
    width: "46px"
    height: "46px"
  website-brand-symbol:
    textColor: "{colors.text}"
  website-button-primary:
    backgroundColor: "{colors.website-accent}"
    textColor: "{colors.website-accent-ink}"
    typography: "{typography.website-action}"
    rounded: "{rounded.pill}"
    padding: "13px 26px"
  website-button-primary-hover:
    backgroundColor: "{colors.website-accent-hover}"
  website-button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.pill}"
    padding: "13px 26px"
  website-window:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.website-window}"
  website-environment-picker:
    backgroundColor: "{colors.subtle}"
    rounded: "{rounded.pill}"
    padding: "3px"
  website-environment-selected:
    backgroundColor: "{colors.website-accent-surface}"
    textColor: "{colors.website-accent}"
    rounded: "{rounded.pill}"
    padding: "8px 11px"
  website-motion-toggle:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.pill}"
    padding: "8px 12px"
---

# Design System: Agents Vault

## Overview

**Creative North Star: "Focused settings"**

Agents Vault uses a quiet, compact settings language for local credential administration. Neutral surfaces and clear label/value relationships carry the interface. Rounded controls, restrained system typography, and immediate state feedback express the user-approved Apple and shadcn/HeroUI direction.

Dark is the initial appearance, using three principal near-black surface tones. The main canvas uses the darkest tone, grouped panels use the middle tone, and compact details and selection states use the lightest tone. Pure black is excluded from these surfaces by the user-approved palette refinement. An optional light palette uses the same semantic roles. The operator interface is semantic UI with vector icons; it does not depend on photography or shipping raster artwork. The operator guidance is extracted from `web/src/styles.css` and the components in `web/src/App.tsx`.

The public website applies the same rounded Apple and shadcn direction at a more spacious reading scale. Its named direction is **Readable projects with deliberate access**: neutral windows, readable configuration, and a restrained lavender accent for actions and connection feedback. Self-hosted Geist sans and Geist Mono add precise typographic hierarchy, while structural rails and section dividers organize the public canvas. Website tokens are scoped with `website-`; the console retains its neutral primary actions. Public runtime sources are `website/src/styles/landing.css`, `website/src/styles/docs.css`, and the Astro scene components. The registered [public surface brief](.impeccable/surfaces/website-src-pages-index-astro.md) owns the landing composition and reading sequence.

**Key Characteristics:**

- Three near-black surface tones in dark mode, with neutral text and a separate light appearance.
- Compact pill actions and gently rounded grouped settings.
- Flat surfaces separated by tone and thin borders.
- Functional system type with explicit heading and control hierarchy.
- Brief state transitions with static feedback under reduced motion.
- Public pages use Geist headings and prose, Geist Mono configuration, structural rails, flat rounded windows, and lavender action and trace feedback.

## Colors

The operator palette distinguishes surfaces through neutral tone. The public website adds a lavender accent within that neutral field. Frontmatter values record the default dark palette and the implemented light replacements; CSS custom properties remain the runtime source.

### Primary

- **Primary:** high-contrast action fill, paired with primary ink for readable action text. The fill is pale in dark mode and dark in light mode.
- **Primary Ink:** text inside the filled primary action.

### Public Website Accent

- **Soft Lavender:** the public brand tile, primary actions, keyboard focus, selected environment labels, connector endpoints, delivery traces, and highlighted configuration references. The hover tone lightens filled actions; the deep ink role keeps their text and the tiled glyph readable. The accent surface supports the selected environment segment.
- **Reading Accent:** documentation uses the public accent in dark appearance and a deeper purple with pale supporting fill in light appearance. These replacements are scoped to Starlight's documentation theme.

### Neutral

- **Background:** the outer stage and the main operator shell in dark mode, forming the darkest canvas. Dark-mode current navigation segments also use this tone.
- **Surface:** form-field fill in both themes and the operator shell fill in light mode. Dark-mode inactive navigation hover and light-mode current navigation segments use this tone. In dark mode it shares the middle tone with panel.
- **Panel:** the credential selector, grouped settings, and sign-in surfaces. Light mode also uses it for search fields and credential icon tiles.
- **Subtle:** segmented navigation tracks, brand and empty-state icon tiles, feedback banners, and command blocks. Light mode also uses it for badges and setting icon tiles. In dark mode it also fills search fields, credential icon tiles, counts, badges, and version labels, forming the lightest compact-detail tone.
- **Hover:** hovered and selected credential rows and secondary-action hover fill. Light-mode inactive navigation hover also uses this role. In dark mode, hover shares the lightest tone with subtle.
- **Border:** shell outlines, grouped rows, field strokes, and dividers.
- **Text:** headings, labels, values, selection fill, and keyboard focus outlines.
- **Muted:** descriptions, supporting metadata, inactive navigation, and secondary icons.

- **Public Divider:** subdued page rails, section boundaries, and the configuration-and-release divider. It organizes the reading grid without the stronger border role used by windows and controls.

### Named Rules

**The Neutral Roles Rule.** Apply the same semantic color roles in both themes; appearance changes their values, not the information hierarchy.

**The Darkest Canvas Rule.** Keep the dark main canvas at the background tone; panels and compact details step lighter above it.

**The Public Accent Rule.** Use the website accent for actions, focus, selection, and delivery feedback; retain neutral surfaces and the operator console's existing primary roles.

## Typography

**Operator Heading and Body Font:** the platform system stack, falling through Apple system typography, BlinkMacSystemFont, Segoe UI, and sans-serif.

**Operator Character:** the hierarchy is functional and restrained. Slightly tightened headings, medium control weights, and muted smaller descriptions keep the operator's values and actions easy to scan. System typography is an explicit user choice.

### Hierarchy

- **Headline:** page heading; the frontmatter records its desktop size, reduced to (26px) below the narrow breakpoint.
- **Detail Title:** selected credential or request title; reduced to (22px) on narrow screens. Long identifiers may wrap anywhere.
- **Title:** section and empty-state headings. Empty-state and sign-in titles tighten letter spacing (-0.02em); the workspace section title retains normal spacing.
- **Body:** default prose and layout text. Supporting detail copy commonly uses (13px).
- **Control:** pill buttons, navigation, and emphasized row labels.
- **Label:** form labels; descriptions and session metadata also use (12px) at normal weight.
- **Caption:** settings descriptions, field hints, footer notes, and limits metadata. Badges use the same size at weight (500).

The sign-in introduction has a contextual heading at (32px), weight (650), line height (1.15), and letter spacing (-0.025em), reduced to (27px) on narrow screens. Command text uses the browser's preformatted monospace face at (12px); no branded mono font is defined. Supporting prose is bounded where needed, including empty-state copy (40ch), introductory copy (42ch), and fine print (68ch).

### Public Website Hierarchy

**Public Sans:** Geist variable, with the existing platform sans stack as fallback. **Public Mono:** Geist Mono variable, falling through UI monospace, SFMono-Regular, Consolas, and monospace. Both font faces are served locally from `website/public/fonts/`, support weights (100–900), and use `font-display: swap`. The shared `website/src/styles/fonts.css` is imported by landing and documentation styles. The font assets are bundled from the official `geist` package (1.7.2) with the SIL Open Font License (1.1).

The public display heading uses the website display token at weight (600), with a larger, closely spaced two-line treatment and balanced wrapping. Introductory copy is (21px) with line height (1.5), reduced to (17px) on intermediate widths. Section headings use the website headline token and reduce to (32px), then (30px). Longer section copy uses the website body token and stays within (72ch); flow and video introductions use (75ch). Configuration uses the website code stack, with tabular line numbers and responsive sizes. Documentation prose uses (.96rem), line height (1.75), and a (72ch) measure. It shares Geist sans, Geist Mono for code, and tightened heading spacing. Filename headings use Geist Mono to distinguish configuration from explanatory prose.

## Layout

The outer stage uses the stage spacing step and centers a shell with maximum width (1380px). The desktop shell spans at least the viewport height minus the surrounding (64px). Its header uses three columns with centered segmented navigation, while the content area uses padding (38px 34px 40px).

The operator's credential surface uses a selector column (300px), a flexible detail column, and gap (34px). Grouped settings align an icon tile, label/description, and value or control. Actions wrap with the control-gap spacing step. Approval and workspace settings surfaces have maximum widths (900px) and (880px), respectively.

At (1100px) and below, navigation moves to a second header row, the selector narrows to (250px), and settings values wrap beneath labels. At (640px) and below, stage padding becomes (12px), main content padding becomes (26px 18px), the credential surface stacks into one column, and the sign-in composition also stacks. Approval metadata changes from four columns to two. Long identifiers and commands wrap rather than forcing overflow.

The Actions editor uses the workspace settings width with three columns of limit fields and gap (16px), stacked into one column at (600px) and below. The separate MCP Apps review uses a single column with maximum width (760px), padding (24px), and thin dividers between label/value pairs; its padding reduces to (16px) at the same breakpoint.

Spacing is compact around individual controls and wider between sections. It is an observed collection of values rather than a strict mathematical grid. Reuse the recorded spacing steps where the same role recurs.

### Public Website Layout

The landing canvas centers a shell up to (1416px) wide with desktop side space (60px), intermediate side space (32px), and compact side space (18px). The hero pairs a large left-aligned introduction with offset project and reference windows. Intermediate desktop widths scale the composition proportionally. Below (800px), the hero and supporting two-column sections stack; below (500px), the windows become fully readable sequential blocks and the delivery flow becomes vertical. Preserve text and diagram legibility when adapting the registered surface.

Single-pixel structural rails sit outside the content shell at (28px) on wide screens, (18px) at intermediate widths, and (12px) on compact screens. The configuration-and-release statement has dividers above and below; its supporting copy is separated by a vertical rule where the layout permits. Configuration, action review, and explainer sections begin with the same divider role. These lines establish a reading grid across the otherwise flat canvas.

Lower sections have generous spacing using the website section steps. The local configuration output and action review list align with explanatory copy on wide screens. The explainer occupies the available width at its native (16:9) ratio. Documentation has a (48rem) content width and (17rem) sidebar; search, theme choice, and Markdown tools stay within its reading layout.

## Elevation & Depth

The operator implementation uses no box shadows. Tone changes and single-pixel borders distinguish the outer shell, grouped settings, selected rows, and fields. The sign-in panel uses the panel tone to separate authentication from its surrounding surface.

The public website also uses no box shadows. Overlap, stacking order, tonal fills, and single-pixel outlines establish the relationship between the project and reference windows. Reference details sit directly on their window surface in separated rows. Flow nodes, configuration output, video, and the limits panel retain this flat material character.

### Named Rules

**The Flat Surface Rule.** Use tonal layering and borders for the existing settings materials; preserve their flat resting appearance.

## Shapes

Actions and segmented navigation use fully rounded pills. Fields and icon tiles use the field radius; badges are smaller rounded rectangles. Credential rows and feedback banners use the row radius, settings groups use the group radius, and the main shell uses the shell radius. The narrow shell uses the panel radius. Groups and the shell clip content at their corners.

Vector icons are normally (18px) with stroke width (1.65). Icon-only controls use circular silhouettes. Selected and inactive status are expressed through tone, labels, and iconography rather than color-coded decoration.

Public project and credential-reference windows use the website project-window radius; placeholder output, flow nodes, video, and the limits panel use the website window radius. Credential-reference details use transparent rows with bottom dividers; the final row omits its divider. Connection paths use a curved corner and round endpoints. Public diagrams are CSS geometry with inline stroke SVG icons; the landing uses (22px) base icons at stroke width (1.5). Desktop overlap becomes stacked windows on compact screens.

The public brand glyph is a compact, closed A/V formed by two interlocking filled pieces. The A has a symmetric roof and triangular aperture, with rounded exterior junctions and balanced band widths. The canonical tile uses website accent fill and ink; the standalone glyph uses the pale text role. Both are native vector shapes independent of Geist or any other font.

## Components

### Buttons

Compact pill actions carry the interface's main decisions.

- **Primary:** primary fill and primary ink; control typography and padding recorded in frontmatter, with minimum height (36px).
- **Secondary:** transparent fill with a single-pixel border; hover applies the hover tone.
- **Text:** smaller underlined muted text; hover changes to the text role.
- **Icon:** circular control (32px); hover adds the hover tone and text color.
- **State:** primary hover lowers opacity to (0.9). Disabled buttons lower opacity to (0.45) and use the unavailable cursor. Enabled buttons scale to (0.98) while pressed.
- **Focus:** keyboard focus uses a (2px) text-colored outline with offset (4px). Header icon actions reduce the offset to (2px), navigation segments inset it to (-2px), and the brand link uses offset (3px) with the field radius.

Button background changes and navigation background/color changes use (160ms ease-out). Reduced motion removes transitions and the pressed scale, retaining static color and outline feedback.

### Chips

Badges, counts, and credential versions are passive metadata. They use subtle fill in both themes, muted text, the badge radius, and compact padding recorded in frontmatter. They do not present interactive filter or selection behavior.

### Cards / Containers

Settings groups and approval containers use the group radius and a single-pixel border. Settings groups and the credential selector use panel fill; approval containers retain the surrounding shell fill. Settings rows use padding (19px 20px), separate with single-pixel dividers, and omit the final divider. Approval containers use panel spacing internally. The credential selector uses padding (18px 12px). The sign-in panel uses the panel radius and padding (28px), reduced to (22px) on narrow screens. All use the flat depth strategy.

### Inputs / Fields

Form fields use surface fill, text-colored content, a single-pixel border, and the field radius. Search uses a pill-shaped subtle-tone wrapper in dark mode and panel-tone wrapper in light mode, with padding (8px 11px), a muted search icon, and a transparent inner field at (12px). Placeholders remain muted at full opacity. Keyboard focus follows the shared outline; the search input uses a larger outline offset (8px).

Errors appear in a feedback banner with an icon and explanatory text; the error variant changes its border to muted. The source does not define a separate per-field invalid style.

The Actions editor extends the same rounded field geometry to selects and textareas, using subtle fill and minimum height (38px). Its labels use (13px) at weight (500). Full destination and credential version remain visible beneath the credential select even when the option text is clipped; long destinations wrap. Arguments are separate resizable textareas with adjacent removal controls.

### Navigation

Segmented navigation uses a subtle pill track with gaps (3px). Segments use compact control typography and padding (8px 16px). The current page is marked with `aria-current="page"` and text color. Dark mode uses background-tone fill for the current segment and surface-tone fill for inactive hover; the current segment retains its background-tone fill on hover. Light mode uses surface-tone current fill and hover-tone inactive hover. Inactive segments use muted text; hover restores text color. Keyboard focus uses a (2px) text-colored outline inset by (-2px), keeping it visible inside the track. Header icon actions use outline offset (2px); the brand link uses offset (3px) and the field radius. The narrow layout stretches the track across its header row and reduces segment padding to (8px 10px) and text to (11px). At (600px) and below, the five destinations, including Actions, wrap within a rounded group (18px) with gap (2px), horizontal segment padding (8px), and text (12px); all destinations remain visible.

### Credential Selection and Inline Settings

Credential selection combines an icon tile, identifier, host, and trailing chevron. Selected rows use `aria-pressed="true"` and hover fill; pointer hover uses the same fill. Credential and setting icon tiles use subtle fill in dark mode; light mode uses panel and subtle fill respectively. Detail changes preserve the grouped icon/label/value vocabulary. Inline editors expand within the current content area and receive heading focus when opened. Empty states center an icon tile, title, and bounded explanatory copy.

### Public Brand Mark

`website/public/brand/av-mark.svg` is the canonical lavender tile with a dark interlocking A/V glyph. `website/public/brand/av-symbol.svg` contains the exact same two glyph paths in pale white, without the tile. Preserve the filled silhouettes, negative space, and relative placement of both pieces; reuse these assets for public brand treatments.

The landing header and delivery broker node use the canonical tile at (46px) and (45px), respectively. The header reduces to (31px) on compact screens, and the documentation title uses (34px). These placements are static; the surrounding name or heading supplies the accessible label. Content preparation derives `/favicon.svg` from the canonical tile, keeping the public icon consistent with the site mark.

### Public Website Actions and Navigation

Public calls to action use larger pill geometry and a minimum desktop height of (50px), reducing to (44px) on compact screens. Primary actions use website accent fill and ink; secondary actions use a border and neutral hover fill. Keyboard focus uses a (2px) accent outline with offset (5px). State changes use (160ms ease-out) when motion is allowed. The public header pairs the product name with Documentation and GitHub links; compact layouts retain both destinations.

### Public Configuration and Delivery Scenes

The project scene uses overlapping flat windows, numbered schema-2 configuration, and a lavender-highlighted credential reference. Reference, access policy, and default grants are transparent rows inside their shared window, separated with bottom borders. A curved connector relates the readable project to its reference details. The lower flow presents the command, broker, and HTTPS provider with labeled rails and an explicit illustrative synthetic-action caption. Both diagrams remain understandable when static.

The environment picker is a labeled group of buttons using `aria-pressed`. Selection changes only the public `APP_ENV` example and announces the illustrative output; the credential remains an unresolved placeholder. It performs no credential lookup. Its selected segment uses website accent-surface fill and website accent text, with inset focus offset (-2px).

Connection traces use a (6s) cycle with `cubic-bezier(.16, 1, .3, 1)` easing; the outbound flow starts (3s) later. Animation runs only while its scene is visible and the document is active. The pause control applies to these traces and changes to Resume animations when paused. Reduced motion keeps static paths and state feedback, removes transitions and smooth scrolling, and hides the unnecessary motion control. The video has independent native playback controls.

### Public Explainer and Reading Tools

The locally served (37-second), silent Forma explainer uses English captions, illustrative synthetic data, a poster, native controls, and MP4/WebM sources. A selectable WebVTT track and Markdown transcript accompany the video; editable source and provenance live in `website/media-source/`. Keep factual custody and platform limits visible in the media and surrounding copy. The video does not autoplay.

Documentation preserves Starlight navigation, Pagefind search, and dark/light/system appearance. Read Markdown and Copy page use the generated direct Markdown files; copy feedback provides a direct-link recovery. Rounded search and reading controls follow the same compact geometry, with accent-colored keyboard focus.

## Do's and Don'ts

### Do:

- **Do** use semantic neutral roles consistently across dark and light appearances.
- **Do** keep the dark main canvas at the darkest background tone.
- **Do** preserve compact pill actions, rounded fields, and flat bordered groups.
- **Do** keep supporting metadata muted while headings, values, and focus use the text role.
- **Do** provide visible keyboard focus and retain static state feedback under reduced motion.
- **Do** allow long identifiers, hosts, and command previews to wrap.
- **Do** scope the lavender accent and Geist typography to the public website and preserve its flat neutral window materials.
- **Do** reuse the canonical public tile or standalone glyph and preserve the two-piece geometry.
- **Do** align structural rails and section dividers with the public reading grid and keep reference details in separated rows.
- **Do** retain readable static scenes, visible keyboard focus, and the local-only placeholder behavior.
- **Do** keep media captions and transcript synchronized with the illustrative synthetic story and factual limits.

### Don't:

- **Don't** introduce teal or blue accent styling into the operator console's approved neutral world.
- **Don't** use pure black for dark surfaces; preserve the three near-black surface tones.
- **Don't** replace the operator console's user-selected system typography with a decorative display face.
- **Don't** rely on shadows or raster artwork to explain the existing settings hierarchy.
- **Don't** turn passive badges into controls without explicit interactive semantics.
- **Don't** use maturity labels in public copy; state the actual delivery, custody, and platform limits.
- **Don't** treat illustrative configuration, diagrams, or media as live vault access or evidence of production custody.
