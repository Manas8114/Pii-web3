import os
import sys
from enhanced_fraud_detector import EnhancedFraudDetector
import json
import fitz  # PyMuPDF

def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file."""
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    doc.close()
    return text

def test_fraud_detector(pdf_path):
    """Test the enhanced fraud detector on a PDF file."""
    if not os.path.exists(pdf_path):
        print(f"Error: File {pdf_path} not found.")
        return
    
    # Extract text from PDF
    text = extract_text_from_pdf(pdf_path)
    
    # Create some mock sensitive data (normally this would come from your PII detection system)
    # Adjust this based on the content of your test PDF
    mock_sensitive_data = {
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
    
    # Initialize and run the fraud detector
    detector = EnhancedFraudDetector()
    results = detector.analyze_document(pdf_path, text, mock_sensitive_data)
    
    # Print results
    print("\n===== ENHANCED FRAUD DETECTION RESULTS =====\n")
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
    
    print("\nForensic Analysis:")
    for key, value in results['forensics'].items():
        print(f"  {key}: {value}")
    
    print("\nSecurity Features:")
    for key, value in results['security_features'].items():
        print(f"  {key}: {value}")
    
    # Save results to JSON file
    output_file = pdf_path.replace('.pdf', '_fraud_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_fraud_detector.py <path_to_pdf>")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    test_fraud_detector(pdf_path) 