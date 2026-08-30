# Release process

The release workflow is manually gated. A live run requires the `main` ref, `live=true`, and the exact confirmation `publish`. The live job has `id-token: write` and no Cargo registry token, so crates.io must be configured with a trusted publisher for repository `LioRael/lenso-email-smtp-plugin`, workflow `.github/workflows/release-plz.yml`, and environment `release`.

Run the dry-run workflow first. The email Capability dependency must already be published from `lenso-notification-plugin`; the immutable git revision remains the source-build pin until registry publication is available.

