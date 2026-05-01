"""
PhishGuard — utils/screenshot.py
Screenshot capture and pre-processing utilities.

The Chrome Extension captures screenshots using chrome.tabs.captureVisibleTab()
and sends them as base64 data-URLs. This module provides server-side
utilities for decoding, validating, and pre-processing those screenshots
before they are passed to the MobileNetV2 CNN.

Also provides a standalone headless capture function (Playwright) used
for server-side screenshot capture when the extension screenshot is unavailable
(e.g., for API testing or batch scanning).
"""

import asyncio
import base64
import io
import logging
from typing import Optional

from PIL import Image

logger = logging.getLogger("phishguard.screenshot")

TARGET_SIZE = (224, 224)   # MobileNetV2 input size


# ─────────────────────────────────────────────
# Base64 decode + preprocess
# ─────────────────────────────────────────────
def decode_screenshot(screenshot_b64: str) -> Optional[Image.Image]:
    """
    Decode a base64 screenshot (from chrome.tabs.captureVisibleTab) to PIL Image.

    Accepts:
      - Raw base64 string
      - Data-URL: 'data:image/png;base64,iVBOR...'

    Returns:
      PIL Image in RGB mode, or None on failure.
    """
    if not screenshot_b64:
        return None

    try:
        if "," in screenshot_b64:
            screenshot_b64 = screenshot_b64.split(",", 1)[1]

        # Pad base64 if needed
        missing_padding = len(screenshot_b64) % 4
        if missing_padding:
            screenshot_b64 += "=" * (4 - missing_padding)

        image_bytes = base64.b64decode(screenshot_b64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return image

    except Exception as e:
        logger.error(f"Screenshot decode error: {e}")
        return None


def preprocess_for_cnn(image: Image.Image) -> Image.Image:
    """
    Resize and convert image to the format expected by the CNN.
    Returns a 224×224 RGB PIL Image.

    Note: Final ToTensor + Normalize transforms are applied inside VisualModel
    using torchvision.transforms — this function handles the PIL-level preprocessing.
    """
    # High-quality Lanczos downsampling preserves logo/brand features better than bilinear
    return image.resize(TARGET_SIZE, Image.LANCZOS)


def validate_screenshot(screenshot_b64: str) -> dict:
    """
    Validate a base64 screenshot payload.
    Returns {'valid': bool, 'reason': str, 'width': int, 'height': int}.
    """
    if not screenshot_b64:
        return {"valid": False, "reason": "Empty screenshot payload", "width": 0, "height": 0}

    if len(screenshot_b64) > 5_000_000:
        return {"valid": False, "reason": "Payload exceeds 5MB limit", "width": 0, "height": 0}

    image = decode_screenshot(screenshot_b64)
    if image is None:
        return {"valid": False, "reason": "Failed to decode base64 image", "width": 0, "height": 0}

    w, h = image.size
    if w < 50 or h < 50:
        return {"valid": False, "reason": f"Image too small: {w}×{h}", "width": w, "height": h}

    return {"valid": True, "reason": "ok", "width": w, "height": h}


def encode_to_b64(image: Image.Image, format: str = "PNG") -> str:
    """Convert a PIL Image back to a base64 data-URL string."""
    buffer = io.BytesIO()
    image.save(buffer, format=format)
    buffer.seek(0)
    encoded = base64.b64encode(buffer.read()).decode("utf-8")
    mime = "image/png" if format.upper() == "PNG" else "image/jpeg"
    return f"data:{mime};base64,{encoded}"


# ─────────────────────────────────────────────
# Headless screenshot capture (Playwright)
# Used for server-side testing / batch scanning
# ─────────────────────────────────────────────
async def capture_screenshot_headless(url: str, timeout_ms: int = 10000) -> Optional[str]:
    """
    Capture a full-viewport screenshot of a URL using Playwright (headless Chromium).

    Returns base64-encoded PNG data-URL, or None on failure.

    Prerequisites:
        pip install playwright
        playwright install chromium

    This function is NOT called during normal extension use — the Chrome Extension
    captures screenshots client-side via chrome.tabs.captureVisibleTab().
    This is provided for:
      - Backend integration tests
      - Batch URL scanning via the API
      - Development testing without the extension
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.error(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
        return None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                ],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True,
            )
            page = await context.new_page()

            # Block heavy resources to speed up load
            await page.route(
                "**/*.{mp4,mp3,woff,woff2,ttf,otf,eot}",
                lambda route: route.abort(),
            )

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Brief wait for dynamic content
                await asyncio.sleep(0.5)
            except Exception as nav_err:
                logger.warning(f"Navigation warning for {url}: {nav_err}")
                # Continue anyway — partial page is still useful for CNN

            screenshot_bytes = await page.screenshot(
                full_page=False,   # Viewport only (matches extension behaviour)
                type="png",
            )

            await browser.close()

            encoded = base64.b64encode(screenshot_bytes).decode("utf-8")
            return f"data:image/png;base64,{encoded}"

    except Exception as e:
        logger.error(f"Headless screenshot failed for {url}: {e}")
        return None
