# Explainer media source

The 37-second silent explainer was authored with Forma's native composition runtime. All example values and action limits are illustrative; protected-custody and host-confinement limitations remain visible. The website supplies burned English captions, a selectable WebVTT track, and a separate transcript.

The opening A/V symbol closes once by translating its two native vector pieces into place. The header and broker marks use the same closed geometry without repeated animation. The source bundles both public brand SVG variants.

`agents-vault-explainer-source.zip` contains editable JSX, the complete timeline, local fonts and licenses, and runtime resource provenance. Extract it and follow its README to edit or export with Forma. `script.json` is the canonical caption text; keep the transcript and VTT synchronized when changing it. Exported MP4, WebM, poster, captions and transcript live in `../public/media/`.

`poster-provenance.json` records the original rendered frame and source hashes. The poster was extracted at 2.5 seconds from the video; it was not produced by a generative image model. Embedded source metadata may change the poster's file hash without changing its pixels. Final exported media is tracked; capture logs and intermediate frames are not.
