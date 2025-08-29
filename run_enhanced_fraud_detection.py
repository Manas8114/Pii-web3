import os
import sys
import json
import fitz  # PyMuPDF
from enhanced_fraud_detector import EnhancedFraudDetector
from datetime import datetime

def process_document(pdf_path, output_dir="enhanced_results"):
    """Process a document using the enhanced fraud detector."""
    if not os.path.exists(pdf_path):
        print(f"Error: File {pdf_path} not found.")
        return None
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    filename = os.path.basename(pdf_path)
    output_json = os.path.join(output_dir, filename.replace('.pdf', '_enhanced_fraud.json'))
    
    # Extract text from PDF
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    doc.close()
    
    # For demonstration purposes, we'll create some mock sensitive data
    # In a real application, you would use your actual PII detection system
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
        },
        "4111 1111 1111 1111": {
            "entity": "CREDIT_CARD",
            "confidence_score": 0.97
        }
    }
    
    # Initialize and run the enhanced fraud detector
    detector = EnhancedFraudDetector()
    results = detector.analyze_document(pdf_path, text, mock_sensitive_data)
    
    # Prepare data structure for the app
    processed_data = {
        "filename": filename,
        "processed_filename": f"enhanced_{filename}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sensitive_data": mock_sensitive_data,
        "pii_count": len(mock_sensitive_data),
        
        # Enhanced fraud detection results
        "fraud_score": results["fraud_score"],
        "fraud_indicators": results["fraud_indicators"],
        "fraud_categories": results["fraud_categories"],
        "forensics": results["forensics"],
        "content_analysis": results["content_analysis"],
        "security_features": results["security_features"],
        "risk_level": results["overall_risk"],
        "risk_percentage": results["risk_percentage"],
        
        # Original text
        "extracted_text": text
    }
    
    # Save results
    with open(output_json, 'w') as f:
        json.dump(processed_data, f, indent=2)
    
    print(f"\n===== ENHANCED FRAUD DETECTION RESULTS =====\n")
    print(f"Processed: {filename}")
    print(f"Overall Risk: {results['overall_risk']} ({results['risk_percentage']:.2f}%)")
    print(f"Fraud Score: {results['fraud_score']:.4f}")
    
    print("\nFraud Indicators:")
    for indicator in results['fraud_indicators']:
        print(f"- {indicator}")
    
    print(f"\nResults saved to {output_json}")
    
    return processed_data

def process_from_models_uploads(filename, upload_dir="Models/static/uploads", output_dir="enhanced_results"):
    """Process a document from the application uploads directory."""
    pdf_path = os.path.join(upload_dir, filename)
    return process_document(pdf_path, output_dir)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_enhanced_fraud_detection.py <path_to_pdf>")
        print("   or: python run_enhanced_fraud_detection.py --from-uploads <filename>")
        sys.exit(1)
    
    if sys.argv[1] == "--from-uploads" and len(sys.argv) >= 3:
        # Process a file from the uploads directory
        filename = sys.argv[2]
        process_from_models_uploads(filename)
    else:
        # Process a file from the specified path
        pdf_path = sys.argv[1]
        process_document(pdf_path) 