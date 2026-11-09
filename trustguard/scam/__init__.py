"""Engine 2a: explainable scam and hoax detection for message text and senders."""
from .analyzer import TextAnalysis, analyze_text, combine, detect_language, mitigations
from .indicators import INDICATORS

__all__ = ["analyze_text", "combine", "mitigations", "detect_language", "TextAnalysis", "INDICATORS"]
