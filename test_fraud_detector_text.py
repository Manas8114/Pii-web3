import sys
from enhanced_fraud_detector import EnhancedFraudDetector
import json

def test_fraud_detector_text(text, sensitive_data=None):
    """Test the enhanced fraud detector on text input."""
    # If no sensitive data provided, create mock data
    if sensitive_data is None:
        sensitive_data = {
            "John Doe": {
                "entity": "PERSON",
                "confidence_score": 0.95
            },
            "123-45-6789": {
                "entity": "US_SSN",
                "confidence_score": 0.98
            },
            "ABCDE1234F": {
                "entity": "IN_PAN",
                "confidence_score": 0.99
            }
        }
    
    # Initialize and run the fraud detector in text-only mode
    detector = EnhancedFraudDetector()
    results = detector.analyze_document_text_only(text, sensitive_data)
    
    # Print results
    print("\n===== ENHANCED FRAUD DETECTION RESULTS (TEXT ONLY) =====\n")
    print(f"Overall Risk: {results['overall_risk']} ({results['risk_percentage']:.2f}%)")
    print(f"Fraud Score: {results['fraud_score']:.4f}")
    
    print("\nFraud Indicators:")
    for indicator in results['fraud_indicators']:
        print(f"- {indicator}")
    
    print("\nDetailed Categories:")
    for category, details in results['fraud_categories'].items():
        print(f"\n{category.replace('_', ' ').title()}")
        print(f"  Score: {details['score']:.2f}")
        print(f"  Description: {details['description']}")
    
    # Save results to JSON file
    output_file = "fraud_analysis_text.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_file}")
    
    return results

if __name__ == "__main__":
    # Example text with various fraud indicators
    sample_text = """
    URGENT ACTION REQUIRED: Your account has been suspended!
    
    Dear Valued Customer,
    
    This is to inform you that your bank account #12345678 has been temporarily suspended due to suspicious activity.
    
    Please verify your identity immediately by clicking the link below and providing your credentials.
    You must reset your password within 24 hours or your account will be permanently terminated.
    
    We are offering a special promotion for verified users - a chance to win $1,000,000 in our lottery!
    
    If you have any questions, contact our legal department at legal@example.com or our emergency helpline.
    
    Reference dates: 12/15/2023 and 06/20/2024
    Invoice amounts: $1,234.56, $2,345.67, $3,456.78, $8,000.00
    
    PAN: ABCDE1234F
    Aadhaar: 1234 5678 9012
    Contact: John Doe, Jane Smith, Robert Johnson
    
    This document was prepared on 01/15/2023 and is valid until 01/15/2028.
    
    Regards,
    Banking Security Team
    """
    
    # Run the test
    test_fraud_detector_text(sample_text) 