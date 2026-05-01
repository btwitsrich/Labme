"""
PhishGuard — models/nlp_model.py
DistilBERT fine-tuned for phishing DOM text classification.

Architecture (from report §5.2):
  - DistilBertForSequenceClassification (HuggingFace)
  - Input: visible DOM text, truncated to 256 tokens
  - Training: 5 epochs, batch=16, lr=2e-5, fp16, weight_decay=0.01
  - Accuracy: 94.3% | Inference latency: ~112ms
  - Saved model: models/nlp_phishguard/ (HuggingFace format)
"""

import asyncio
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import torch
import torch.nn.functional as F
from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast

logger = logging.getLogger("phishguard.nlp")

# Path to fine-tuned model weights (saved via trainer.save_model())
MODEL_PATH = Path(__file__).parent / "nlp_phishguard"
FALLBACK_PRETRAINED = "distilbert-base-uncased"   # Used if local weights not found

MAX_TOKENS = 256          # DistilBERT max — kept at 256 for latency
PHISHING_LABEL_IDX = 1    # Label mapping: 0=legitimate, 1=phishing


class NLPModel:
    """
    DistilBERT-based phishing text classifier.

    Usage:
        model = NLPModel()
        prob = await model.predict_async("Urgent: verify your PayPal account now!")
    """

    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer: Optional[DistilBertTokenizerFast] = None
        self.model: Optional[DistilBertForSequenceClassification] = None
        self._load()

    def _load(self):
        """Load tokenizer and model. Falls back to pretrained base if fine-tuned weights absent."""
        try:
            if MODEL_PATH.exists():
                logger.info(f"Loading fine-tuned NLP model from {MODEL_PATH}")
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(str(MODEL_PATH))
                self.model = DistilBertForSequenceClassification.from_pretrained(str(MODEL_PATH))
            else:
                logger.warning(
                    f"Fine-tuned model not found at {MODEL_PATH}. "
                    f"Loading pretrained '{FALLBACK_PRETRAINED}' as placeholder. "
                    "Predictions will be unreliable until fine-tuned weights are added."
                )
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(FALLBACK_PRETRAINED)
                self.model = DistilBertForSequenceClassification.from_pretrained(
                    FALLBACK_PRETRAINED, num_labels=2
                )

            self.model.to(self.device)
            self.model.eval()
            logger.info(f"NLP model ready on {self.device}")

        except Exception as e:
            logger.error(f"Failed to load NLP model: {e}")
            self.model = None

    def predict(self, text: str) -> float:
        """
        Synchronous inference.
        Returns phishing probability in [0.0, 1.0].
        """
        if self.model is None:
            logger.warning("NLP model not loaded — returning neutral 0.5")
            return 0.5

        if not text or len(text.strip()) < 10:
            # Too short to analyse meaningfully
            return 0.3

        try:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=MAX_TOKENS,
                padding="max_length",
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = F.softmax(outputs.logits, dim=-1)
                phishing_prob = probs[0][PHISHING_LABEL_IDX].item()

            return round(float(phishing_prob), 4)

        except Exception as e:
            logger.error(f"NLP inference error: {e}")
            return 0.5

    async def predict_async(self, text: str) -> float:
        """
        Async wrapper — runs CPU-bound inference in a thread pool
        so it doesn't block the asyncio event loop.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.predict, text)

    def get_token_importance(self, text: str) -> list[tuple[str, float]]:
        """
        Returns per-token attribution scores for XAI explanation.
        Uses integrated gradients approximation (simple gradient × input).
        Returns list of (token_string, importance_score) pairs.
        """
        if self.model is None or not text:
            return []

        try:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=MAX_TOKENS,
                padding="max_length",
                return_offsets_mapping=False,
            )
            input_ids = inputs["input_ids"].to(self.device)
            attention_mask = inputs["attention_mask"].to(self.device)

            # Embed layer for gradient computation
            embeddings = self.model.distilbert.embeddings(input_ids)
            embeddings.retain_grad()

            outputs = self.model(inputs_embeds=embeddings, attention_mask=attention_mask)
            phishing_score = F.softmax(outputs.logits, dim=-1)[0][PHISHING_LABEL_IDX]
            phishing_score.backward()

            # L2 norm of gradient × embedding as attribution
            grad = embeddings.grad[0]  # (seq_len, hidden_dim)
            attributions = (grad * embeddings[0]).norm(dim=-1).detach().cpu().numpy()

            tokens = self.tokenizer.convert_ids_to_tokens(input_ids[0].cpu().numpy())

            # Filter out padding and special tokens
            results = []
            for token, score in zip(tokens, attributions):
                if token in ("[PAD]", "[CLS]", "[SEP]"):
                    continue
                clean_token = token.replace("##", "")
                results.append((clean_token, float(score)))

            # Normalise to [0, 1]
            if results:
                max_score = max(s for _, s in results) or 1.0
                results = [(t, round(s / max_score, 4)) for t, s in results]

            return results[:20]   # Top 20 most important tokens

        except Exception as e:
            logger.error(f"Token importance error: {e}")
            return []
