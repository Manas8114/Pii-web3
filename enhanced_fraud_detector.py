"""
Enhanced Fraud Detection System with Blockchain Integration
Combines AI-powered fraud detection with blockchain audit trails
"""

import json
import logging
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from dataclasses import dataclass
from Models.blockchain_audit import BlockchainAuditManager

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    import cv2
except ImportError:
    cv2 = None

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FraudDetectionResult:
    """Data class for fraud detection results"""
    fraud_probability: float
    risk_level: str
    suspicious_patterns: List[str]
    confidence_score: float
    analysis_details: Dict[str, Any]
    blockchain_hash: Optional[str] = None
    audit_trail_id: Optional[str] = None

class EnhancedFraudDetector:
    """Enhanced fraud detection system with blockchain integration"""
    
    def __init__(self, blockchain_network: str = "testnet"):
        self.blockchain_manager = BlockchainAuditManager(network=blockchain_network)
        
        # Enhanced fraud patterns with weights
        self.fraud_patterns = {
            # Document structure anomalies
            "unusual_formatting": {
                "patterns": ["inconsistent_fonts", "suspicious_spacing", "altered_alignment"],
                "weight": 0.3,
                "description": "Document formatting inconsistencies"
            },
            
            # Content-based patterns
            "suspicious_content": {
                "patterns": ["duplicate_text", "overlapping_elements", "hidden_text"],
                "weight": 0.4,
                "description": "Suspicious content patterns"
            },
            
            # Metadata analysis
            "metadata_anomalies": {
                "patterns": ["creation_date_mismatch", "multiple_authors", "suspicious_tools"],
                "weight": 0.25,
                "description": "Document metadata inconsistencies"
            },
            
            # Statistical anomalies
            "statistical_outliers": {
                "patterns": ["unusual_file_size", "compression_anomalies", "pixel_analysis"],
                "weight": 0.35,
                "description": "Statistical analysis anomalies"
            },
            
            # Digital forensics
            "digital_forensics": {
                "patterns": ["copy_paste_detection", "image_splicing", "font_analysis"],
                "weight": 0.45,
                "description": "Digital forensics indicators"
            }
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.8
        }
    
    def analyze_document(self, file_path: str, metadata: Dict[str, Any] = None) -> FraudDetectionResult:
        """
        Perform comprehensive fraud analysis on a document
        """
        try:
            logger.info(f"Starting enhanced fraud analysis for: {file_path}")
            
            # Initialize analysis components
            analysis_results = {
                "structural_analysis": self._analyze_structure(file_path),
                "content_analysis": self._analyze_content(file_path),
                "metadata_analysis": self._analyze_metadata(file_path, metadata or {}),
                "statistical_analysis": self._statistical_analysis(file_path),
                "digital_forensics": self._digital_forensics_analysis(file_path)
            }
            
            # Calculate overall fraud probability
            fraud_probability = self._calculate_fraud_probability(analysis_results)
            
            # Determine risk level
            risk_level = self._determine_risk_level(fraud_probability)
            
            # Extract suspicious patterns
            suspicious_patterns = self._extract_suspicious_patterns(analysis_results)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(analysis_results)
            
            # Create comprehensive analysis details
            analysis_details = {
                "timestamp": datetime.now().isoformat(),
                "file_path": file_path,
                "analysis_components": analysis_results,
                "pattern_matches": suspicious_patterns,
                "risk_factors": self._identify_risk_factors(analysis_results),
                "recommendations": self._generate_recommendations(fraud_probability, suspicious_patterns)
            }
            
            # Create fraud detection result
            result = FraudDetectionResult(
                fraud_probability=fraud_probability,
                risk_level=risk_level,
                suspicious_patterns=suspicious_patterns,
                confidence_score=confidence_score,
                analysis_details=analysis_details
            )
            
            # Register analysis on blockchain
            blockchain_result = self._register_on_blockchain(file_path, result, metadata or {})
            if blockchain_result.get("success"):
                result.blockchain_hash = blockchain_result.get("document_hash")
                result.audit_trail_id = blockchain_result.get("transaction_hash")
            
            logger.info(f"Fraud analysis completed. Risk Level: {risk_level}, Probability: {fraud_probability:.3f}")
            return result
            
        except Exception as e:
            logger.error(f"Error in fraud analysis: {str(e)}")
            raise
    
    def _analyze_structure(self, file_path: str) -> Dict[str, Any]:
        """Analyze document structure for anomalies using PyMuPDF."""
        try:
            ext = os.path.splitext(file_path)[1].lower()
            anomalies: List[str] = []

            if ext == '.pdf' and fitz:
                doc = fitz.open(file_path)

                # --- Font consistency ---
                all_fonts: set = set()
                for page in doc:
                    for f in page.get_fonts(full=True):
                        all_fonts.add(f[3])  # font name
                unique_font_count = len(all_fonts)
                font_consistency = max(0.0, 1.0 - (unique_font_count - 1) * 0.15)
                if unique_font_count > 5:
                    anomalies.append("inconsistent_fonts")

                # --- Layout regularity (page-size variance) ---
                widths = [p.rect.width for p in doc]
                heights = [p.rect.height for p in doc]
                size_variance = float(np.std(widths) + np.std(heights))
                layout_regularity = max(0.0, 1.0 - size_variance / 100.0)
                if size_variance > 20:
                    anomalies.append("irregular_layout")

                # --- Formatting (annotation count as proxy) ---
                total_annots = sum(len(list(p.annots() or [])) for p in doc)
                formatting_consistency = max(0.0, 1.0 - total_annots * 0.05)
                if total_annots > 10:
                    anomalies.append("formatting_inconsistencies")

                # --- Element alignment (text-block vertical alignment) ---
                alignment_scores: List[float] = []
                for page in doc:
                    blocks = page.get_text("blocks")
                    if len(blocks) > 1:
                        x0s = [b[0] for b in blocks]
                        alignment_scores.append(max(0.0, 1.0 - float(np.std(x0s)) / 50.0))
                element_alignment = float(np.mean(alignment_scores)) if alignment_scores else 0.8

                doc.close()
            else:
                # For images or unsupported types give neutral scores
                font_consistency = 0.8
                layout_regularity = 0.8
                formatting_consistency = 0.8
                element_alignment = 0.8

            structural_scores = {
                "font_consistency": round(font_consistency, 3),
                "layout_regularity": round(layout_regularity, 3),
                "formatting_consistency": round(formatting_consistency, 3),
                "element_alignment": round(element_alignment, 3),
            }
            overall_score = float(np.mean(list(structural_scores.values())))

            return {
                "scores": structural_scores,
                "anomalies": anomalies,
                "overall_score": round(overall_score, 3),
                "analysis_method": "structural_analysis_v3.0_real",
            }
        except Exception as e:
            logger.error(f"Error in structural analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _analyze_content(self, file_path: str) -> Dict[str, Any]:
        """Analyze document content for suspicious patterns using real text extraction."""
        try:
            ext = os.path.splitext(file_path)[1].lower()
            text = ""

            if ext == '.pdf' and fitz:
                doc = fitz.open(file_path)
                text = "\n".join(page.get_text() for page in doc)
                doc.close()

            # --- Text authenticity (ratio of printable chars) ---
            if text:
                printable_ratio = sum(c.isprintable() or c.isspace() for c in text) / max(len(text), 1)
                text_authenticity = round(printable_ratio, 3)
            else:
                text_authenticity = 0.8

            # --- Logical flow (average sentence length variance) ---
            sentences = [s.strip() for s in text.replace('\n', ' ').split('.') if s.strip()]
            if len(sentences) > 2:
                lengths = [len(s.split()) for s in sentences]
                cv = float(np.std(lengths)) / max(float(np.mean(lengths)), 1)
                logical_flow = round(max(0.0, 1.0 - cv * 0.5), 3)
            else:
                logical_flow = 0.8

            # --- Language consistency (unique-word ratio) ---
            words = text.lower().split()
            if words:
                language_consistency = round(min(1.0, len(set(words)) / max(len(words), 1) * 2), 3)
            else:
                language_consistency = 0.8

            # --- Content coherence (presence of repeated long phrases) ---
            from collections import Counter
            trigrams = [' '.join(words[i:i+3]) for i in range(len(words)-2)]
            trigram_counts = Counter(trigrams)
            repeated = sum(1 for c in trigram_counts.values() if c > 3)
            content_coherence = round(max(0.0, 1.0 - repeated * 0.05), 3)

            suspicious_content: List[str] = []
            if text_authenticity < 0.4:
                suspicious_content.append("potential_text_manipulation")
            if logical_flow < 0.5:
                suspicious_content.append("illogical_content_flow")
            if repeated > 5:
                suspicious_content.append("duplicate_text")

            content_scores = {
                "text_authenticity": text_authenticity,
                "logical_flow": logical_flow,
                "language_consistency": language_consistency,
                "content_coherence": content_coherence,
            }
            overall_score = float(np.mean(list(content_scores.values())))

            return {
                "scores": content_scores,
                "suspicious_patterns": suspicious_content,
                "overall_score": round(overall_score, 3),
                "text_analysis_confidence": round(min(1.0, len(text) / 500), 3),
                "analysis_method": "nlp_content_analysis_v4.0_real",
            }
        except Exception as e:
            logger.error(f"Error in content analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _analyze_metadata(self, file_path: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze document metadata for inconsistencies using real file metadata."""
        try:
            ext = os.path.splitext(file_path)[1].lower()
            metadata_anomalies: List[str] = []

            creation_date_validity = 0.8
            author_consistency = 0.8
            modification_history = 0.8
            tool_authenticity = 0.8

            if ext == '.pdf' and fitz:
                doc = fitz.open(file_path)
                pdf_meta = doc.metadata or {}
                doc.close()

                # Creation date validity
                creation = pdf_meta.get('creationDate', '')
                mod_date = pdf_meta.get('modDate', '')
                if creation and mod_date and creation > mod_date:
                    creation_date_validity = 0.3
                    metadata_anomalies.append("suspicious_creation_date")
                elif not creation:
                    creation_date_validity = 0.5

                # Author consistency
                author = pdf_meta.get('author', '')
                producer = pdf_meta.get('producer', '')
                creator = pdf_meta.get('creator', '')
                if author and creator and author.lower() != creator.lower():
                    author_consistency = 0.5
                    metadata_anomalies.append("author_inconsistency")
                if not author:
                    author_consistency = 0.6

                # Modification history
                if creation and mod_date and creation != mod_date:
                    modification_history = 0.7
                elif not mod_date:
                    modification_history = 0.6
                    metadata_anomalies.append("suspicious_modifications")

                # Tool authenticity
                suspicious_tools = ['phantomjs', 'wkhtmltopdf', 'unknown']
                if any(t in producer.lower() for t in suspicious_tools):
                    tool_authenticity = 0.4
                    metadata_anomalies.append("suspicious_tool_used")

            metadata_scores = {
                "creation_date_validity": round(creation_date_validity, 3),
                "author_consistency": round(author_consistency, 3),
                "modification_history": round(modification_history, 3),
                "tool_authenticity": round(tool_authenticity, 3),
            }
            overall_score = float(np.mean(list(metadata_scores.values())))

            return {
                "scores": metadata_scores,
                "anomalies": metadata_anomalies,
                "overall_score": round(overall_score, 3),
                "metadata_available": len(metadata) > 0,
                "analysis_method": "metadata_forensics_v3.0_real",
            }
        except Exception as e:
            logger.error(f"Error in metadata analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _statistical_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform statistical analysis using real file properties."""
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            ext = os.path.splitext(file_path)[1].lower()
            outliers: List[str] = []

            # --- File size analysis ---
            expected_ranges = {
                '.pdf': (5_000, 20_000_000),
                '.png': (1_000, 10_000_000),
                '.jpg': (1_000, 10_000_000),
                '.jpeg': (1_000, 10_000_000),
            }
            lo, hi = expected_ranges.get(ext, (100, 50_000_000))
            if lo <= file_size <= hi:
                file_size_score = 0.9
            elif file_size < lo:
                file_size_score = 0.3
                outliers.append("unusual_file_size")
            else:
                file_size_score = 0.5
                outliers.append("unusual_file_size")

            # --- Compression ratio (actual vs raw for PDF) ---
            compression_score = 0.8
            if ext == '.pdf' and fitz:
                doc = fitz.open(file_path)
                total_text_len = sum(len(page.get_text()) for page in doc)
                doc.close()
                ratio = total_text_len / max(file_size, 1)
                compression_score = round(max(0.2, min(1.0, ratio * 5)), 3)
                if compression_score < 0.4:
                    outliers.append("compression_anomaly")

            # --- Pixel distribution (for images) ---
            pixel_score = 0.8
            if ext in ('.png', '.jpg', '.jpeg') and cv2 is not None:
                img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
                if img is not None:
                    hist = cv2.calcHist([img], [0], None, [256], [0, 256]).flatten()
                    hist_norm = hist / hist.sum()
                    entropy = -np.sum(hist_norm[hist_norm > 0] * np.log2(hist_norm[hist_norm > 0]))
                    pixel_score = round(min(1.0, entropy / 8.0), 3)
                    if pixel_score < 0.3:
                        outliers.append("pixel_distribution_anomaly")

            # --- Frequency analysis (byte entropy) ---
            with open(file_path, 'rb') as f:
                data = f.read(min(file_size, 100_000))  # sample first 100KB
            byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            byte_freq = byte_counts / byte_counts.sum()
            byte_entropy = -np.sum(byte_freq[byte_freq > 0] * np.log2(byte_freq[byte_freq > 0]))
            frequency_score = round(min(1.0, byte_entropy / 8.0), 3)

            statistical_scores = {
                "file_size_analysis": round(file_size_score, 3),
                "compression_ratio": round(compression_score, 3),
                "pixel_distribution": round(pixel_score, 3),
                "frequency_analysis": round(frequency_score, 3),
            }
            overall_score = float(np.mean(list(statistical_scores.values())))

            return {
                "scores": statistical_scores,
                "outliers": outliers,
                "overall_score": round(overall_score, 3),
                "statistical_confidence": round(min(1.0, file_size / 10_000), 3),
                "analysis_method": "advanced_statistical_analysis_v5.0_real",
            }
        except Exception as e:
            logger.error(f"Error in statistical analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _digital_forensics_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform digital forensics using real file hash and image analysis."""
        try:
            ext = os.path.splitext(file_path)[1].lower()
            forensic_evidence: List[str] = []

            # --- Hash integrity (compute SHA-256) ---
            sha = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha.update(chunk)
            file_hash = sha.hexdigest()
            hash_integrity = 1.0  # valid by definition — stored for audit

            # --- Digital signature validation (PDF) ---
            sig_score = 0.8
            if ext == '.pdf' and fitz:
                doc = fitz.open(file_path)
                has_sig = any(
                    annot.type[1] == 'Widget' and '/Sig' in str(annot.info)
                    for page in doc for annot in (page.annots() or [])
                )
                sig_score = 0.9 if has_sig else 0.6
                if not has_sig:
                    forensic_evidence.append("no_digital_signature")
                doc.close()

            # --- Copy-paste / duplicate region detection (images) ---
            copy_paste_score = 0.8
            image_manipulation_score = 0.8
            if ext in ('.png', '.jpg', '.jpeg') and cv2 is not None:
                img = cv2.imread(file_path)
                if img is not None:
                    # Error Level Analysis (ELA) approximation
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    lap = cv2.Laplacian(gray, cv2.CV_64F)
                    variance = float(lap.var())
                    # High variance can indicate manipulation
                    image_manipulation_score = round(max(0.2, min(1.0, 1.0 - variance / 5000)), 3)
                    if image_manipulation_score < 0.5:
                        forensic_evidence.append("image_manipulation_detected")

                    # Simple duplicate-block check (downscale + self-match)
                    small = cv2.resize(gray, (64, 64))
                    result = cv2.matchTemplate(gray, small, cv2.TM_CCOEFF_NORMED)
                    high_matches = int(np.sum(result > 0.9))
                    copy_paste_score = round(max(0.2, 1.0 - high_matches * 0.01), 3)
                    if high_matches > 50:
                        forensic_evidence.append("potential_copy_paste")

            forensics_scores = {
                "copy_paste_detection": round(copy_paste_score, 3),
                "image_manipulation": round(image_manipulation_score, 3),
                "digital_signature_validation": round(sig_score, 3),
                "hash_integrity": round(hash_integrity, 3),
            }
            overall_score = float(np.mean(list(forensics_scores.values())))

            return {
                "scores": forensics_scores,
                "evidence": forensic_evidence,
                "overall_score": round(overall_score, 3),
                "file_hash_sha256": file_hash,
                "forensics_confidence": round(min(1.0, os.path.getsize(file_path) / 50_000), 3),
                "analysis_method": "digital_forensics_suite_v6.0_real",
            }
        except Exception as e:
            logger.error(f"Error in digital forensics analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _calculate_fraud_probability(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate overall fraud probability from analysis results"""
        try:
            # Weight the different analysis components
            weights = {
                "structural_analysis": 0.2,
                "content_analysis": 0.25,
                "metadata_analysis": 0.15,
                "statistical_analysis": 0.2,
                "digital_forensics": 0.2
            }
            
            weighted_score = 0.0
            total_weight = 0.0
            
            for component, weight in weights.items():
                if component in analysis_results and "overall_score" in analysis_results[component]:
                    # Convert score to fraud probability (invert good scores)
                    fraud_component = 1.0 - analysis_results[component]["overall_score"]
                    weighted_score += fraud_component * weight
                    total_weight += weight
            
            # Normalize by total weight
            if total_weight > 0:
                fraud_probability = weighted_score / total_weight
            else:
                fraud_probability = 0.5  # Default uncertainty
            
            # Ensure probability is between 0 and 1
            fraud_probability = max(0.0, min(1.0, fraud_probability))
            
            return fraud_probability
            
        except Exception as e:
            logger.error(f"Error calculating fraud probability: {str(e)}")
            return 0.5  # Return neutral probability on error
    
    def _determine_risk_level(self, fraud_probability: float) -> str:
        """Determine risk level based on fraud probability"""
        if fraud_probability >= self.risk_thresholds["high"]:
            return "High"
        elif fraud_probability >= self.risk_thresholds["medium"]:
            return "Medium"
        else:
            return "Low"
    
    def _extract_suspicious_patterns(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract all suspicious patterns from analysis results"""
        patterns = []
        
        for component, results in analysis_results.items():
            if isinstance(results, dict):
                # Check for anomalies, outliers, evidence, etc.
                for key in ["anomalies", "outliers", "evidence", "suspicious_patterns"]:
                    if key in results and isinstance(results[key], list):
                        patterns.extend(results[key])
        
        return list(set(patterns))  # Remove duplicates
    
    def _calculate_confidence_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate confidence score for the analysis"""
        confidence_scores = []
        
        for component, results in analysis_results.items():
            if isinstance(results, dict):
                # Look for confidence indicators
                for key in ["statistical_confidence", "forensics_confidence", "text_analysis_confidence"]:
                    if key in results:
                        confidence_scores.append(results[key])
                
                # Use overall score as confidence indicator if no specific confidence
                if not confidence_scores and "overall_score" in results:
                    confidence_scores.append(results["overall_score"])
        
        if confidence_scores:
            return float(np.mean(confidence_scores))
        else:
            return 0.7  # Default confidence
    
    def _identify_risk_factors(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Identify key risk factors from analysis"""
        risk_factors = []
        
        for component, results in analysis_results.items():
            if isinstance(results, dict) and "overall_score" in results:
                score = results["overall_score"]
                if score < 0.4:  # Low score indicates high risk
                    risk_factors.append(f"Low {component.replace('_', ' ')} score ({score:.2f})")
        
        return risk_factors
    
    def _generate_recommendations(self, fraud_probability: float, suspicious_patterns: List[str]) -> List[str]:
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        if fraud_probability > 0.8:
            recommendations.extend([
                "Document requires immediate manual review",
                "Consider rejecting document due to high fraud probability",
                "Perform additional verification steps"
            ])
        elif fraud_probability > 0.6:
            recommendations.extend([
                "Document requires careful review",
                "Verify document authenticity through alternative channels",
                "Request additional supporting documents"
            ])
        elif fraud_probability > 0.3:
            recommendations.extend([
                "Document may require additional verification",
                "Monitor for patterns in similar documents"
            ])
        else:
            recommendations.append("Document appears authentic based on analysis")
        
        # Add pattern-specific recommendations
        if "font_inconsistency" in suspicious_patterns:
            recommendations.append("Verify document creation process due to font inconsistencies")
        if "image_manipulation_detected" in suspicious_patterns:
            recommendations.append("Investigate potential image manipulation")
        
        return recommendations
    
    def _register_on_blockchain(self, file_path: str, result: FraudDetectionResult, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Register fraud analysis results on blockchain"""
        try:
            # Prepare blockchain metadata
            blockchain_metadata = {
                **metadata,
                "fraud_analysis": {
                    "fraud_probability": result.fraud_probability,
                    "risk_level": result.risk_level,
                    "confidence_score": result.confidence_score,
                    "suspicious_patterns_count": len(result.suspicious_patterns),
                    "analysis_timestamp": datetime.now().isoformat()
                },
                "analysis_type": "enhanced_fraud_detection",
                "analyzer_version": "v2.1"
            }
            
            # Read file content for hashing
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Generate document hash
            document_hash = self.blockchain_manager.generate_document_hash(file_content, blockchain_metadata)
            
            # Register on blockchain
            registration_result = self.blockchain_manager.register_document(
                document_hash, 
                blockchain_metadata
            )
            
            # Create audit trail for the analysis
            if registration_result.get("success"):
                audit_steps = [
                    {"step": "fraud_analysis_initiated", "timestamp": datetime.now().isoformat()},
                    {"step": "structural_analysis_completed", "result": "completed"},
                    {"step": "content_analysis_completed", "result": "completed"},
                    {"step": "metadata_analysis_completed", "result": "completed"},
                    {"step": "statistical_analysis_completed", "result": "completed"},
                    {"step": "digital_forensics_completed", "result": "completed"},
                    {"step": "fraud_probability_calculated", "value": result.fraud_probability},
                    {"step": "risk_level_determined", "value": result.risk_level},
                    {"step": "analysis_completed", "timestamp": datetime.now().isoformat()}
                ]
                
                self.blockchain_manager.create_audit_trail(document_hash, audit_steps)
            
            return registration_result
            
        except Exception as e:
            logger.error(f"Error registering fraud analysis on blockchain: {str(e)}")
            return {"success": False, "error": str(e)}

def analyze_document_fraud(file_path: str, metadata: Dict[str, Any] = None, blockchain_network: str = "testnet") -> FraudDetectionResult:
    """
    Convenience function to perform fraud analysis on a document
    """
    detector = EnhancedFraudDetector(blockchain_network=blockchain_network)
    return detector.analyze_document(file_path, metadata)

if __name__ == "__main__":
    # Test the enhanced fraud detector
    print("Testing Enhanced Fraud Detector...")
    
    # Create test detector
    detector = EnhancedFraudDetector(blockchain_network="testnet")
    
    # Test metadata
    test_metadata = {
        "filename": "test_document.pdf",
        "upload_source": "web_interface",
        "user_id": "test_user_123"
    }
    
    # Note: This would need an actual file path in real usage
    # result = detector.analyze_document("test_file.pdf", test_metadata)
    
    print("Enhanced Fraud Detector initialized successfully!")
    print(f"Risk thresholds: {detector.risk_thresholds}")
    print(f"Fraud patterns configured: {len(detector.fraud_patterns)}")
