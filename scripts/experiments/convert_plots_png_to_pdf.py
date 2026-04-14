#!/usr/bin/env python3
"""One-shot tool: wrap every experiment-results/**/plots/*.png into a PDF.

This is a retrofit for existing PNG figures that were produced before we
switched every runner to emit PDF directly. It does not re-render the
figures from raw data (so the resulting PDFs embed raster pixels at the
original matplotlib DPI, not vector paths). If you want a true vector
PDF for a specific figure, rerun the owning experiment — all runners
now emit PDF natively as of commit f914111.

Behaviour:
  - Walks all `experiment-results/**/plots/` directories.
  - For each `figure_*.png`, produces a sibling `figure_*.pdf` if it
    does not already exist.
  - Leaves the original PNG in place unless `--delete-png` is passed,
    so any markdown reports that already link to `.png` keep rendering.
  - `--overwrite` regenerates `.pdf` files that already exist (useful
    if you edited the PNG or want to pick up a fixed aspect ratio).
  - `--root DIR` points at a different root (default: experiment-results).
  - `--dry-run` prints what would happen without writing files.

Implementation strategy: matplotlib.image.imread the PNG as an ndarray,
create a single-axes figure sized to the image's intrinsic pixels at
the same DPI the original runners used (180), and savefig the result
as PDF. This produces a 1-page PDF whose content stream embeds the
PNG's pixel array — visually identical to the original PNG, no
resampling.

This script deliberately avoids Pillow / ImageMagick / sips so it can
run on any host that already has matplotlib installed (the same
dependency the runners themselves check for).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, List, Tuple


def find_png_plots(root: Path) -> List[Path]:
    """Return every figure_*.png beneath a plots/ directory under `root`."""
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("figure_*.png") if p.parent.name == "plots")


def convert_one(
    png_path: Path,
    *,
    overwrite: bool,
    dry_run: bool,
    dpi: float,
) -> Tuple[str, Path]:
    """Convert a single PNG to a sibling PDF. Returns (action, pdf_path)."""
    pdf_path = png_path.with_suffix(".pdf")
    if pdf_path.exists() and not overwrite:
        return ("skip-exists", pdf_path)
    if dry_run:
        return ("would-convert", pdf_path)

    # Lazy import so --help works on hosts without matplotlib.
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.image as mpimg
    import matplotlib.pyplot as plt

    img = mpimg.imread(str(png_path))
    if img.ndim == 2:
        h, w = img.shape
    else:
        h, w, _ = img.shape

    # Sizing: preserve the intrinsic pixel dimensions at the given DPI
    # so the resulting PDF page renders byte-for-byte the same pixels
    # as the source PNG at the same scale.
    fig_w_in = w / dpi
    fig_h_in = h / dpi

    fig = plt.figure(figsize=(fig_w_in, fig_h_in), dpi=dpi)
    ax = fig.add_axes([0.0, 0.0, 1.0, 1.0])
    ax.imshow(img, interpolation="none", aspect="auto")
    ax.set_axis_off()
    fig.savefig(pdf_path, format="pdf", bbox_inches="tight", pad_inches=0)
    plt.close(fig)
    return ("converted", pdf_path)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Retrofit existing PNG figures under experiment-results/ to PDF.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("experiment-results"),
        help="Directory to walk (default: experiment-results).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Regenerate PDFs that already exist.",
    )
    parser.add_argument(
        "--delete-png",
        action="store_true",
        help="Delete the source PNG after a successful conversion. "
             "Off by default so markdown reports that embed .png keep rendering.",
    )
    parser.add_argument(
        "--dpi",
        type=float,
        default=180.0,
        help="DPI to reproduce the original matplotlib figures at (default: 180).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would happen without writing anything.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    root = args.root.resolve()
    plots = find_png_plots(root)
    if not plots:
        print(f"[convert] no figure_*.png under {root}/**/plots/", flush=True)
        return 0

    print(f"[convert] root={root}", flush=True)
    print(f"[convert] found {len(plots)} PNG files", flush=True)
    if args.dry_run:
        print("[convert] --dry-run: no files will be written", flush=True)

    counts = {"converted": 0, "skip-exists": 0, "would-convert": 0, "failed": 0}
    for png in plots:
        try:
            action, pdf = convert_one(
                png,
                overwrite=args.overwrite,
                dry_run=args.dry_run,
                dpi=args.dpi,
            )
        except Exception as exc:  # noqa: BLE001
            counts["failed"] += 1
            print(f"[convert] FAIL {png.relative_to(root)}  {type(exc).__name__}: {exc}",
                  file=sys.stderr, flush=True)
            continue
        counts[action] += 1
        tag = action
        rel_pdf = pdf.relative_to(root)
        print(f"[convert] {tag:>14}  {rel_pdf}", flush=True)

        if action == "converted" and args.delete_png and not args.dry_run:
            try:
                png.unlink()
                print(f"[convert]      deleted  {png.relative_to(root)}", flush=True)
            except OSError as exc:
                print(f"[convert]  delete-FAIL  {png.relative_to(root)}  {exc}",
                      file=sys.stderr, flush=True)

    print(
        f"[convert] done: converted={counts['converted']} "
        f"skipped={counts['skip-exists']} would_convert={counts['would-convert']} "
        f"failed={counts['failed']}",
        flush=True,
    )
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
