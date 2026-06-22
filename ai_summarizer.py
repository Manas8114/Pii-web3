"""
AI Document Summarizer — Privacy-Preserving Document Insights
Uses Google Gemini to summarize already-redacted text, ensuring no PII leaks to the LLM.
"""

import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Lazy-load Gemini to avoid blocking startup
_model = None
_available = None


def _ensure_model():
    """Initialize the Gemini model on first use."""
    global _model, _available
    if _available is not None:
        return _available

    api_key = os.getenv('GEMINI_API_KEY', '')
    if not api_key:
        logger.warning("GEMINI_API_KEY not set — AI summarization will use demo mode")
        _available = False
        return False

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        _model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            generation_config={
                "temperature": 0.3,
                "top_p": 0.9,
                "max_output_tokens": 1024,
            }
        )
        _available = True
        logger.info("✅ Gemini AI summarizer initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Gemini: {e}")
        _available = False
        return False


def generate_summary(redacted_text: str, pii_count: int = 0, fraud_risk: str = "Unknown") -> Dict[str, Any]:
    """
    Generate a privacy-preserving summary of a redacted document.
    
    Args:
        redacted_text: The document text AFTER PII redaction
        pii_count: Number of PII entities detected
        fraud_risk: Risk level from fraud detection
    
    Returns:
        dict with summary, document_type, key_findings, and risk_assessment
    """
    if not redacted_text or len(redacted_text.strip()) < 20:
        return {
            "summary": "Document contains insufficient text for analysis.",
            "document_type": "Unknown",
            "key_findings": [],
            "risk_assessment": "Unable to assess — insufficient content.",
            "ai_powered": False
        }

    if not _ensure_model():
        return _demo_summary(redacted_text, pii_count, fraud_risk)

    try:
        if _model is None:
            return _demo_summary(redacted_text, pii_count, fraud_risk)
            
        _text_sample: str = str(redacted_text)[:3000] if redacted_text else ""  # type: ignore[index]
        prompt = f"""You are a document security analyst. Analyze this REDACTED document text and provide a structured summary.
The document has been pre-processed: all personally identifiable information (PII) has been removed and replaced with [REDACTED] markers. 
Do NOT attempt to guess or reconstruct any redacted information.

REDACTED DOCUMENT TEXT:
---
{_text_sample}
---

SECURITY CONTEXT:
- PII entities detected and redacted: {pii_count}
- Fraud risk level: {fraud_risk}

Respond in this exact format (no markdown, plain text):
DOCUMENT_TYPE: [type of document, e.g., Financial Report, Legal Contract, Medical Record, Personal Letter, etc.]
SUMMARY: [2-3 sentence summary of the document's purpose and content, without referencing any PII]
KEY_FINDINGS:
- [finding 1]
- [finding 2]  
- [finding 3]
RISK_ASSESSMENT: [1-2 sentence assessment of document sensitivity based on PII density and fraud indicators]"""

        response = _model.generate_content(prompt) # type: ignore
        
        if response and response.text:
            return _parse_response(response.text, pii_count)
        else:
            return _demo_summary(redacted_text, pii_count, fraud_risk)

    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return _demo_summary(redacted_text, pii_count, fraud_risk)


def _parse_response(text: str, pii_count: int) -> Dict[str, Any]:
    """Parse Gemini's structured response into a dict."""
    summary: str = ""
    document_type: str = "General Document"
    key_findings: List[str] = []
    risk_assessment: str = ""

    lines = text.strip().split('\n')
    current_section = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("DOCUMENT_TYPE:"):
            document_type = line.replace("DOCUMENT_TYPE:", "").strip()
        elif line.startswith("SUMMARY:"):
            summary = line.replace("SUMMARY:", "").strip()
            current_section = "summary"
        elif line.startswith("KEY_FINDINGS:"):
            current_section = "findings"
        elif line.startswith("RISK_ASSESSMENT:"):
            risk_assessment = line.replace("RISK_ASSESSMENT:", "").strip()
            current_section = "risk"
        elif line.startswith("- ") and current_section == "findings":
            key_findings.append(line[2:].strip())  # type: ignore[index]
        elif current_section is not None:
            if current_section == "summary":
                summary = str(summary) + " " + line
            elif current_section == "risk":
                risk_assessment = str(risk_assessment) + " " + line

    if not key_findings:
        key_findings = [f"{pii_count} PII entities were detected and redacted"]

    return {
        "summary": summary,
        "document_type": document_type,
        "key_findings": key_findings,
        "risk_assessment": risk_assessment,
        "ai_powered": True
    }


def _demo_summary(text: str, pii_count: int, fraud_risk: str) -> Dict[str, Any]:
    """Fallback summary when Gemini API is unavailable."""
    word_count = len(text.split())
    
    if pii_count > 10:
        sensitivity = "HIGH"
        risk_note = "This document contains a significant amount of personally identifiable information and should be handled with care."
    elif pii_count > 3:
        sensitivity = "MEDIUM"
        risk_note = "This document contains moderate PII. Standard data protection measures are recommended."
    else:
        sensitivity = "LOW"
        risk_note = "This document contains minimal PII. Basic data protection measures should suffice."

    return {
        "summary": f"Document processed successfully. Contains approximately {word_count} words with {pii_count} PII entities detected and redacted. Fraud risk assessed as {fraud_risk}.",
        "document_type": "General Document",
        "key_findings": [
            f"{pii_count} personally identifiable information entities detected",
            f"Document sensitivity level: {sensitivity}",
            f"Fraud risk assessment: {fraud_risk}",
        ],
        "risk_assessment": risk_note,
        "ai_powered": False
    }
