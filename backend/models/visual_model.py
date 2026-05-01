"""
PhishGuard — models/visual_model.py
MobileNetV2 CNN for visual brand impersonation detection.

Architecture (from report §5.1):
  - Pre-trained MobileNetV2 backbone (PyTorch / torchvision)
  - Custom 2-class classification head (phishing / legitimate)
  - Input: 224×224 full-viewport screenshot
  - Training: Adam lr=1e-4, Dropout, StepLR scheduler
  - Augmentation: random flip, colour jitter, rotation
  - Accuracy: 96.8% | Saved as: models/mobilenet_phishguard.pth
"""

import asyncio
import base64
import io
import logging
from pathlib import Path
from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
from PIL import Image
from torchvision import models, transforms

logger = logging.getLogger("phishguard.cnn")

MODEL_PATH = Path(__file__).parent / "mobilenet_phishguard.pth"

# ImageNet normalisation statistics (MobileNetV2 was pretrained on ImageNet)
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD  = [0.229, 0.224, 0.225]
INPUT_SIZE    = 224
PHISHING_CLASS_IDX = 1   # 0=legitimate, 1=phishing


def build_model(num_classes: int = 2) -> nn.Module:
    """
    Build MobileNetV2 with a custom classification head.
    Matches the architecture used during training.
    """
    model = models.mobilenet_v2(weights=models.MobileNet_V2_Weights.IMAGENET1K_V1)

    # Replace the default classifier head
    in_features = model.classifier[1].in_features
    model.classifier = nn.Sequential(
        nn.Dropout(p=0.2),
        nn.Linear(in_features, 256),
        nn.ReLU(inplace=True),
        nn.Dropout(p=0.3),
        nn.Linear(256, num_classes),
    )
    return model


class VisualModel:
    """
    MobileNetV2-based screenshot phishing classifier.

    Usage:
        model = VisualModel()
        prob = await model.predict_async(screenshot_b64_string)
    """

    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: Optional[nn.Module] = None
        self.transform = self._build_transform()
        self._load()

    def _build_transform(self) -> transforms.Compose:
        """Inference-time transform pipeline (no augmentation)."""
        return transforms.Compose([
            transforms.Resize((INPUT_SIZE, INPUT_SIZE)),
            transforms.ToTensor(),
            transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
        ])

    def _load(self):
        """Load model weights from disk."""
        try:
            self.model = build_model()

            if MODEL_PATH.exists():
                logger.info(f"Loading CNN weights from {MODEL_PATH}")
                state = torch.load(MODEL_PATH, map_location=self.device, weights_only=True)
                self.model.load_state_dict(state)
                logger.info("CNN weights loaded successfully")
            else:
                logger.warning(
                    f"CNN weights not found at {MODEL_PATH}. "
                    "Using ImageNet-pretrained backbone only — predictions unreliable."
                )

            self.model.to(self.device)
            self.model.eval()
            logger.info(f"CNN model ready on {self.device}")

        except Exception as e:
            logger.error(f"Failed to load CNN model: {e}")
            self.model = None

    def _decode_screenshot(self, screenshot_b64: str) -> Optional[Image.Image]:
        """
        Decode a base64 screenshot string to a PIL Image.
        Handles both raw base64 and data-URL format:
          'data:image/png;base64,iVBOR...'
        """
        if not screenshot_b64:
            return None
        try:
            # Strip data-URL prefix if present
            if "," in screenshot_b64:
                screenshot_b64 = screenshot_b64.split(",", 1)[1]

            image_bytes = base64.b64decode(screenshot_b64)
            image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            return image
        except Exception as e:
            logger.error(f"Screenshot decode error: {e}")
            return None

    def predict(self, screenshot_b64: str) -> float:
        """
        Synchronous inference.
        Returns phishing probability in [0.0, 1.0].
        Falls back to 0.5 if screenshot is missing or invalid.
        """
        if self.model is None:
            logger.warning("CNN model not loaded — returning neutral 0.5")
            return 0.5

        image = self._decode_screenshot(screenshot_b64)
        if image is None:
            return 0.5   # No screenshot → neutral score

        try:
            tensor = self.transform(image).unsqueeze(0).to(self.device)  # (1, 3, 224, 224)

            with torch.no_grad():
                logits = self.model(tensor)
                probs = F.softmax(logits, dim=-1)
                phishing_prob = probs[0][PHISHING_CLASS_IDX].item()

            return round(float(phishing_prob), 4)

        except Exception as e:
            logger.error(f"CNN inference error: {e}")
            return 0.5

    async def predict_async(self, screenshot_b64: str) -> float:
        """Async wrapper — runs in thread pool to avoid blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.predict, screenshot_b64)

    def get_grad_cam(self, screenshot_b64: str) -> Optional[dict]:
        """
        Compute Grad-CAM heatmap for the last convolutional layer.
        Returns a dict with heatmap data for XAI visualisation.
        Used by the XAI explainer to highlight suspicious regions.
        """
        if self.model is None:
            return None

        image = self._decode_screenshot(screenshot_b64)
        if image is None:
            return None

        try:
            tensor = self.transform(image).unsqueeze(0).to(self.device)
            tensor.requires_grad_(True)

            # Hook into the last conv layer of MobileNetV2 features
            activations = []
            gradients = []

            def forward_hook(module, inp, out):
                activations.append(out.detach())

            def backward_hook(module, grad_in, grad_out):
                gradients.append(grad_out[0].detach())

            # Last convolutional block in MobileNetV2
            target_layer = self.model.features[-1]
            fwd = target_layer.register_forward_hook(forward_hook)
            bwd = target_layer.register_full_backward_hook(backward_hook)

            logits = self.model(tensor)
            phishing_score = F.softmax(logits, dim=-1)[0][PHISHING_CLASS_IDX]
            phishing_score.backward()

            fwd.remove()
            bwd.remove()

            # Grad-CAM: weight channels by global average pooled gradient
            grads = gradients[0]            # (1, C, H, W)
            acts  = activations[0]          # (1, C, H, W)
            weights = grads.mean(dim=(2, 3), keepdim=True)   # (1, C, 1, 1)
            cam = (weights * acts).sum(dim=1).squeeze(0)     # (H, W)
            cam = F.relu(cam)
            cam = cam / (cam.max() + 1e-8)

            return {
                "heatmap": cam.cpu().numpy().tolist(),
                "width": cam.shape[1],
                "height": cam.shape[0],
            }

        except Exception as e:
            logger.error(f"Grad-CAM error: {e}")
            return None
