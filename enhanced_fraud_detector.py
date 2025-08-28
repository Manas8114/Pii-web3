"""
Enhanced Fraud Detection System with Blockchain Integration
Combines AI-powered fraud detection with blockchain audit trails
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from dataclasses import dataclass
from Models.blockchain_audit import BlockchainAuditManager

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
        """Analyze document structure for anomalies"""
        try:
            # Simulated structural analysis
            # In a real implementation, this would analyze PDF structure, fonts, layouts, etc.
            
            structural_scores = {
                "font_consistency": np.random.uniform(0.1, 0.9),
                "layout_regularity": np.random.uniform(0.2, 0.8),
                "formatting_consistency": np.random.uniform(0.1, 0.7),
                "element_alignment": np.random.uniform(0.3, 0.9)
            }
            
            # Check for structural anomalies
            anomalies = []
            if structural_scores["font_consistency"] < 0.3:
                anomalies.append("inconsistent_fonts")
            if structural_scores["layout_regularity"] < 0.4:
                anomalies.append("irregular_layout")
            if structural_scores["formatting_consistency"] < 0.3:
                anomalies.append("formatting_inconsistencies")
            
            overall_score = np.mean(list(structural_scores.values()))
            
            return {
                "scores": structural_scores,
                "anomalies": anomalies,
                "overall_score": overall_score,
                "analysis_method": "structural_analysis_v2.1"
            }
            
        except Exception as e:
            logger.error(f"Error in structural analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _analyze_content(self, file_path: str) -> Dict[str, Any]:
        """Analyze document content for suspicious patterns"""
        try:
            # Simulated content analysis
            content_scores = {
                "text_authenticity": np.random.uniform(0.2, 0.9),
                "logical_flow": np.random.uniform(0.3, 0.8),
                "language_consistency": np.random.uniform(0.4, 0.9),
                "content_coherence": np.random.uniform(0.1, 0.8)
            }
            
            # Detect suspicious content patterns
            suspicious_content = []
            if content_scores["text_authenticity"] < 0.4:
                suspicious_content.append("potential_text_manipulation")
            if content_scores["logical_flow"] < 0.5:
                suspicious_content.append("illogical_content_flow")
            
            overall_score = np.mean(list(content_scores.values()))
            
            return {
                "scores": content_scores,
                "suspicious_patterns": suspicious_content,
                "overall_score": overall_score,
                "text_analysis_confidence": np.random.uniform(0.6, 0.95),
                "analysis_method": "nlp_content_analysis_v3.0"
            }
            
        except Exception as e:
            logger.error(f"Error in content analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _analyze_metadata(self, file_path: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze document metadata for inconsistencies"""
        try:
            # Simulated metadata analysis
            metadata_scores = {
                "creation_date_validity": np.random.uniform(0.5, 1.0),
                "author_consistency": np.random.uniform(0.3, 0.9),
                "modification_history": np.random.uniform(0.2, 0.8),
                "tool_authenticity": np.random.uniform(0.4, 0.9)
            }
            
            # Check for metadata anomalies
            metadata_anomalies = []
            if metadata_scores["creation_date_validity"] < 0.6:
                metadata_anomalies.append("suspicious_creation_date")
            if metadata_scores["author_consistency"] < 0.5:
                metadata_anomalies.append("author_inconsistency")
            if metadata_scores["modification_history"] < 0.4:
                metadata_anomalies.append("suspicious_modifications")
            
            overall_score = np.mean(list(metadata_scores.values()))
            
            return {
                "scores": metadata_scores,
                "anomalies": metadata_anomalies,
                "overall_score": overall_score,
                "metadata_available": len(metadata) > 0,
                "analysis_method": "metadata_forensics_v2.3"
            }
            
        except Exception as e:
            logger.error(f"Error in metadata analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _statistical_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform statistical analysis for anomaly detection"""
        try:
            # Simulated statistical analysis
            statistical_scores = {
                "file_size_analysis": np.random.uniform(0.3, 0.9),
                "compression_ratio": np.random.uniform(0.4, 0.8),
                "pixel_distribution": np.random.uniform(0.2, 0.9),
                "frequency_analysis": np.random.uniform(0.1, 0.7)
            }
            
            # Detect statistical outliers
            outliers = []
            if statistical_scores["file_size_analysis"] < 0.4:
                outliers.append("unusual_file_size")
            if statistical_scores["compression_ratio"] < 0.5:
                outliers.append("compression_anomaly")
            if statistical_scores["pixel_distribution"] < 0.3:
                outliers.append("pixel_distribution_anomaly")
            
            overall_score = np.mean(list(statistical_scores.values()))
            
            return {
                "scores": statistical_scores,
                "outliers": outliers,
                "overall_score": overall_score,
                "statistical_confidence": np.random.uniform(0.7, 0.95),
                "analysis_method": "advanced_statistical_analysis_v4.1"
            }
            
        except Exception as e:
            logger.error(f"Error in statistical analysis: {str(e)}")
            return {"error": str(e), "overall_score": 0.5}
    
    def _digital_forensics_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform digital forensics analysis"""
        try:
            # Simulated digital forensics
            forensics_scores = {
                "copy_paste_detection": np.random.uniform(0.2, 0.8),
                "image_manipulation": np.random.uniform(0.1, 0.9),
                "digital_signature_validation": np.random.uniform(0.5, 1.0),
                "hash_integrity": np.random.uniform(0.7, 1.0)
            }
            
            # Detect forensic evidence
            forensic_evidence = []
            if forensics_scores["copy_paste_detection"] > 0.6:
                forensic_evidence.append("potential_copy_paste")
            if forensics_scores["image_manipulation"] > 0.7:
                forensic_evidence.append("image_manipulation_detected")
            if forensics_scores["digital_signature_validation"] < 0.6:
                forensic_evidence.append("signature_issues")
            
            overall_score = np.mean(list(forensics_scores.values()))
            
            return {
                "scores": forensics_scores,
                "evidence": forensic_evidence,
                "overall_score": overall_score,
                "forensics_confidence": np.random.uniform(0.8, 0.98),
                "analysis_method": "digital_forensics_suite_v5.2"
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
