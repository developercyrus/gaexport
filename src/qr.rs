//! QR codes in both directions: reading them out of screenshots/photos and
//! rendering them for re-import.

#[cfg(feature = "qr-decode")]
use anyhow::bail;
use anyhow::{anyhow, Context, Result};
use qrcode::{EcLevel, QrCode};

#[derive(Clone, Copy, Debug)]
pub struct RenderOptions {
    /// Pixels (or SVG units) per QR module.
    pub scale: u32,
    /// Quiet-zone width in modules. The spec requires 4.
    pub quiet_zone: u32,
    pub ec_level: EcLevel,
}

impl Default for RenderOptions {
    fn default() -> Self {
        RenderOptions {
            scale: 8,
            quiet_zone: 4,
            ec_level: EcLevel::M,
        }
    }
}

/// The module matrix: `(width, dark_flags)` in row-major order.
pub fn matrix(data: &str, ec_level: EcLevel) -> Result<(usize, Vec<bool>)> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), ec_level)
        .with_context(|| format!("payload of {} bytes does not fit in a QR code", data.len()))?;
    let width = code.width();
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    Ok((width, dark))
}

/// Renders a PNG. Dark modules are black, quiet zone and light modules white,
/// which is what every scanner expects.
#[cfg(feature = "image-io")]
pub fn render_png(data: &str, opts: RenderOptions) -> Result<Vec<u8>> {
    use image::{codecs::png::PngEncoder, ExtendedColorType, ImageEncoder};

    let (width, dark) = matrix(data, opts.ec_level)?;
    let scale = opts.scale.max(1) as usize;
    let quiet = opts.quiet_zone as usize;
    let side = (width + quiet * 2) * scale;
    let mut pixels = vec![0xffu8; side * side];
    for (index, is_dark) in dark.iter().enumerate() {
        if !*is_dark {
            continue;
        }
        let (mx, my) = (index % width, index / width);
        for dy in 0..scale {
            let y = (my + quiet) * scale + dy;
            let row = y * side;
            let start = row + (mx + quiet) * scale;
            pixels[start..start + scale].fill(0x00);
        }
    }
    let mut out = Vec::new();
    PngEncoder::new(&mut out)
        .write_image(&pixels, side as u32, side as u32, ExtendedColorType::L8)
        .context("encoding PNG")?;
    Ok(out)
}

#[cfg(not(feature = "image-io"))]
pub fn render_png(_data: &str, _opts: RenderOptions) -> Result<Vec<u8>> {
    Err(anyhow!(
        "this build has no PNG support (rebuild with the `image-io` feature); use svg or ansi"
    ))
}

/// Renders a standalone SVG — no dependencies, crisp at any size.
pub fn render_svg(data: &str, opts: RenderOptions) -> Result<String> {
    let (width, dark) = matrix(data, opts.ec_level)?;
    let quiet = opts.quiet_zone;
    let side = (width as u32 + quiet * 2) * opts.scale.max(1);
    let mut svg = String::with_capacity(dark.len() * 48);
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{side}\" height=\"{side}\" \
         viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\">\n\
         <rect width=\"{side}\" height=\"{side}\" fill=\"#ffffff\"/>\n<g fill=\"#000000\">\n"
    ));
    let scale = opts.scale.max(1);
    for (index, is_dark) in dark.iter().enumerate() {
        if !*is_dark {
            continue;
        }
        let x = ((index % width) as u32 + quiet) * scale;
        let y = ((index / width) as u32 + quiet) * scale;
        svg.push_str(&format!(
            "<rect x=\"{x}\" y=\"{y}\" width=\"{scale}\" height=\"{scale}\"/>\n"
        ));
    }
    svg.push_str("</g>\n</svg>\n");
    Ok(svg)
}

/// Renders for a terminal using half-block characters, two module rows per text
/// row. Colours are set explicitly so the code scans on light *and* dark themes.
pub fn render_ansi(data: &str, ec_level: EcLevel) -> Result<String> {
    const RESET: &str = "\x1b[0m";
    const COLORS: &str = "\x1b[47;30m"; // white background, black foreground
    let (width, dark) = matrix(data, ec_level)?;
    let quiet = 2usize; // two text rows/columns is a 4-module quiet zone vertically
    let padded_width = width + quiet * 2;
    let at = |x: usize, y: usize| -> bool {
        if x < quiet || y < quiet || x >= width + quiet || y >= width + quiet {
            return false;
        }
        dark[(y - quiet) * width + (x - quiet)]
    };
    let mut out = String::new();
    let total_rows = width + quiet * 2;
    let mut y = 0;
    while y < total_rows {
        out.push_str(COLORS);
        for x in 0..padded_width {
            let top = at(x, y);
            let bottom = if y + 1 < total_rows {
                at(x, y + 1)
            } else {
                false
            };
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str(RESET);
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

/// Decodes every QR code found in an image file.
#[cfg(feature = "qr-decode")]
pub fn decode_image_file(path: &std::path::Path) -> Result<Vec<String>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decode_image_bytes(&bytes).with_context(|| format!("in {}", path.display()))
}

#[cfg(not(feature = "qr-decode"))]
pub fn decode_image_file(_path: &std::path::Path) -> Result<Vec<String>> {
    Err(anyhow!(
        "this build cannot read QR images (rebuild with the `qr-decode` feature)"
    ))
}

/// Decodes every QR code found in an in-memory image.
///
/// Screenshots and phone photos are messy, so we retry with a few cheap
/// transforms before giving up: 2x nearest-neighbour upscaling helps small
/// screenshots, and inversion handles dark-mode captures.
#[cfg(feature = "qr-decode")]
pub fn decode_image_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let image = image::load_from_memory(bytes).context("not a supported image format")?;
    decode_luma(image.to_luma8())
}

/// Decodes straight from raw RGBA pixels — what a `<canvas>` hands over for a
/// camera frame, so live scanning needs no image encode/decode round trip.
#[cfg(feature = "qr-decode")]
pub fn decode_rgba(pixels: &[u8], width: u32, height: u32) -> Result<Vec<String>> {
    let expected = (width as usize) * (height as usize) * 4;
    if pixels.len() < expected {
        bail!(
            "expected {expected} bytes of RGBA for {width}x{height}, got {}",
            pixels.len()
        );
    }
    let mut luma = image::GrayImage::new(width, height);
    for (index, pixel) in luma.pixels_mut().enumerate() {
        let rgba = &pixels[index * 4..index * 4 + 4];
        // Rec. 601 luma, the same weighting `image` uses for grayscale.
        let value =
            (u32::from(rgba[0]) * 299 + u32::from(rgba[1]) * 587 + u32::from(rgba[2]) * 114) / 1000;
        *pixel = image::Luma([value.min(255) as u8]);
    }
    decode_luma(luma)
}

#[cfg(feature = "qr-decode")]
fn decode_luma(base: image::GrayImage) -> Result<Vec<String>> {
    use image::imageops;

    let mut found: Vec<String> = Vec::new();

    let mut attempts: Vec<image::GrayImage> = vec![base.clone()];
    if base.width() < 900 || base.height() < 900 {
        attempts.push(imageops::resize(
            &base,
            base.width().saturating_mul(2).max(1),
            base.height().saturating_mul(2).max(1),
            imageops::FilterType::Nearest,
        ));
    }
    let mut inverted = base;
    imageops::invert(&mut inverted);
    attempts.push(inverted);

    for candidate in attempts {
        let mut prepared = rqrr::PreparedImage::prepare(candidate);
        for grid in prepared.detect_grids() {
            if let Ok((_meta, content)) = grid.decode() {
                if !content.trim().is_empty() && !found.iter().any(|c| c == &content) {
                    found.push(content);
                }
            }
        }
        if !found.is_empty() {
            break;
        }
    }

    if found.is_empty() {
        return Err(anyhow!(
            "no QR code found — crop the screenshot tighter around the code, or try a sharper capture"
        ));
    }
    Ok(found)
}

#[cfg(not(feature = "qr-decode"))]
pub fn decode_image_bytes(_bytes: &[u8]) -> Result<Vec<String>> {
    Err(anyhow!(
        "this build cannot read QR images (rebuild with the `qr-decode` feature)"
    ))
}

#[cfg(not(feature = "qr-decode"))]
pub fn decode_rgba(_pixels: &[u8], _width: u32, _height: u32) -> Result<Vec<String>> {
    Err(anyhow!(
        "this build cannot read QR images (rebuild with the `qr-decode` feature)"
    ))
}

/// Extensions we treat as images when walking a directory.
pub const IMAGE_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico", "tga", "pnm", "pbm", "pgm",
    "ppm",
];

pub fn looks_like_image_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| IMAGE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// PNG/JPEG/GIF/BMP/WEBP magic bytes, for `-` (stdin) input.
pub fn looks_like_image_bytes(bytes: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"BM",
        b"RIFF",
        b"II*\x00",
        b"MM\x00*",
    ];
    MAGICS.iter().any(|m| bytes.starts_with(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_has_expected_shape() {
        let (width, dark) = matrix("HELLO", EcLevel::M).unwrap();
        assert_eq!(dark.len(), width * width);
        assert!(width >= 21 && width % 4 == 1, "width {width}");
        // Finder pattern: the top-left 7x7 corner starts dark.
        assert!(dark[0]);
    }

    #[test]
    fn svg_is_wellformed() {
        let svg = render_svg(
            "otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ",
            RenderOptions::default(),
        )
        .unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.contains("<rect"));
    }

    #[test]
    fn ansi_rows_are_half_height() {
        let out = render_ansi("HELLO", EcLevel::L).unwrap();
        let (width, _) = matrix("HELLO", EcLevel::L).unwrap();
        let rows = out.lines().count();
        assert_eq!(rows, (width + 4).div_ceil(2));
    }

    #[cfg(feature = "qr-decode")]
    #[test]
    fn png_roundtrips_through_the_decoder() {
        let payload = "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQ&issuer=ACME";
        let png = render_png(payload, RenderOptions::default()).unwrap();
        assert!(looks_like_image_bytes(&png));
        let decoded = decode_image_bytes(&png).unwrap();
        assert_eq!(decoded, vec![payload.to_string()]);
    }

    #[cfg(feature = "qr-decode")]
    #[test]
    fn decodes_from_raw_rgba_pixels() {
        let payload = "otpauth://totp/RGBA:test?secret=GEZDGNBVGY3TQOJQ";
        let png = render_png(payload, RenderOptions::default()).unwrap();
        let gray = image::load_from_memory(&png).unwrap().to_luma8();
        let (w, h) = (gray.width(), gray.height());
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for pixel in gray.pixels() {
            rgba.extend_from_slice(&[pixel.0[0], pixel.0[0], pixel.0[0], 255]);
        }
        assert_eq!(decode_rgba(&rgba, w, h).unwrap(), vec![payload.to_string()]);
        assert!(decode_rgba(&rgba[..10], w, h).is_err());
    }

    #[cfg(feature = "qr-decode")]
    #[test]
    fn decoding_a_blank_image_reports_a_useful_error() {
        let png = {
            use image::{codecs::png::PngEncoder, ExtendedColorType, ImageEncoder};
            let mut out = Vec::new();
            PngEncoder::new(&mut out)
                .write_image(&vec![0xffu8; 64 * 64], 64, 64, ExtendedColorType::L8)
                .unwrap();
            out
        };
        let err = decode_image_bytes(&png).unwrap_err().to_string();
        assert!(err.contains("no QR code found"), "{err}");
    }
}
