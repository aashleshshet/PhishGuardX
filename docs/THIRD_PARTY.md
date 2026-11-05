# Third-party notices

- **Google Sans**, Google Fonts: SIL Open Font License 1.1, bundled at `frontend/public/fonts/OFL.txt`. The self-hosted Latin variable WOFF2 was fetched through Google's official Fonts CSS API. No third-party font request occurs at runtime.
- **Tesseract.js / Tesseract.js-core:** Apache 2.0; bundled worker notices and core license are in `frontend/public/ocr/`. English traineddata was downloaded from the Tesseract.js project language-data distribution at `https://tessdata.projectnaptha.com/4.0.0/eng.traineddata.gz`; Tesseract language data is distributed under Apache 2.0.
- **jsQR:** Apache 2.0; dependency source and license are installed with npm.
- **Lucide icons:** ISC license; dependency source and license are installed with npm.
- **Radix UI / class-variance-authority / Framer Motion:** respective upstream licenses are included in installed packages.
- **Training datasets:** see `DATASETS.md`. No raw email corpus or URL dataset is redistributed here. Trained coefficients and evaluation metadata are included.

Dependency versions are locked in `frontend/package-lock.json`; backend and training requirement versions are pinned separately.
