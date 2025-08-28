from flask import Flask, request, render_template, redirect, url_for, send_file, jsonify
import pytesseract
from PIL import Image
from transformers import pipeline
import os
from werkzeug.utils import secure_filename
import fitz 
import spacy
import cv2
import numpy as np
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from transformers import pipeline
from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts
from typing import List
import firebase_admin
from flask_cors import CORS
from firebase_admin import credentials, firestore
from safetensors.torch import load_file
import torch
import json
import logging
from datetime import datetime

# Import blockchain and enhanced fraud detection modules
try:
    from blockchain_audit import BlockchainAuditManager, create_audit_manager
    BLOCKCHAIN_AVAILABLE = True
except ImportError:
    print("WARNING: Blockchain audit module not available")
    BLOCKCHAIN_AVAILABLE = False

try:
    import sys
    sys.path.append('..')
    from enhanced_fraud_detector import EnhancedFraudDetector, analyze_document_fraud
    FRAUD_DETECTOR_AVAILABLE = True
except ImportError:
    print("WARNING: Enhanced fraud detector not available")
    FRAUD_DETECTOR_AVAILABLE = False

app = Flask(__name__)
CORS(app)  

UPLOAD_FOLDER = 'static/uploads'
OUTPUT_FOLDER = 'outputs'
PROCESSED_FOLDER = 'static/processed'  # Corrected this line
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}

# Flask config
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config["PROCESSED_FOLDER"] = PROCESSED_FOLDER  # Corrected this line

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)  # N



try:
    nlp = spacy.load("en_core_web_lg")
except OSError:
    print("Downloading en_core_web_lg model...")
    os.system("spacy download en_core_web_lg")
    nlp = spacy.load("en_core_web_lg")

transformers_model = pipeline(
    "token-classification",
    model="dbmdz/bert-large-cased-finetuned-conll03-english",
    aggregation_strategy="average",
    ignore_labels=["O", "MISC"]
)

# Load the model weights
model_path = r"D:\CodeFest(tokenization)\Standard-Chartered-Hackthon\Models\model.safetensors"
# state_dict = load_file(model_path)
class TransformersRecognizer(EntityRecognizer):
    def __init__(self, model_pipeline, supported_language="en"):
        self.pipeline = model_pipeline
        self.label2presidio = {
            "PER": "PERSON",
            "LOC": "LOCATION",
            "ORG": "ORGANIZATION",
            "MISC": "MISC",
        }
        super().__init__(supported_entities=list(self.label2presidio.values()), supported_language=supported_language)

    def load(self) -> None:
        pass

    def analyze(self, text: str, entities: List[str] = None, nlp_artifacts: NlpArtifacts = None) -> List[RecognizerResult]:
        results = []
        predicted_entities = self.pipeline(text)

        for e in predicted_entities:
            converted_entity = self.label2presidio.get(e["entity_group"], None)
            if converted_entity and (entities is None or converted_entity in entities):
                results.append(RecognizerResult(entity_type=converted_entity, start=e["start"], end=e["end"], score=e["score"]))
        return results

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

transformers_recognizer = TransformersRecognizer(transformers_model)
analyzer.registry.add_recognizer(transformers_recognizer)

COLOR_MASK = "BLACK"
color_map = {
    "BLACK": (0, 0, 0),
    "WHITE": (1.0, 1.0, 1.0),
    "RED": (1.0, 0.0, 0.0),
    "GREEN": (0.0, 1.0, 0.0),
    "BLUE": (0.0, 0.0, 1.0),
}

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF."""
    doc = fitz.open(pdf_path)
    text = "\n".join(page.get_text("text") for page in doc)
    return text, doc

def extract_text_from_image(image_path):
    """Extract text from image using Tesseract OCR."""
    img = Image.open(image_path)
    text = pytesseract.image_to_string(img)
    return text


def allowed_file(filename):
    """Check if file type is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

import re
import uuid

def generate_secure_token():
    """Generate a unique secure token"""
    return str(uuid.uuid4())


def indian_specific_regex(text):
    """Returns additional sensitive data based on Indian-specific regex patterns"""
    
    regex_patterns = {
        "IN_PAN": r"\b[A-Z]{5}\d{4}[A-Z]{1}\b",  
        "IN_AADHAAR": r"\b\d{4} \d{4} \d{4}\b", 
        "IN_PHONE": r"\b(?:\+91|91)?\d{10}\b",  
        "IN_PHONE_WITHOUT_CODE":r"\b[6789]\d{9}\b",
        # "IN_BANK_ACCOUNT": r"\b\d{9,18}\b"
    }
    
    sensitive_data = {}
    
    for entity_name, pattern in regex_patterns.items():
        matches = re.finditer(pattern, text)
        
        for match in matches:
            entity_text = match.group(0)
            0
            safe_token = generate_secure_token()
            sensitive_data[entity_text] = {
                "entity": entity_name,
                "safe_token": safe_token,
                "confidence_score": 1 
            }
    
    return sensitive_data

# Initialize Firebase with error handling
try:
    cred = credentials.Certificate('serviceAccountKey.json')
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    FIREBASE_AVAILABLE = True
    print("SUCCESS: Firebase initialized successfully")
except Exception as e:
    print(f"WARNING: Firebase initialization failed: {str(e)}")
    db = None
    FIREBASE_AVAILABLE = False

# Initialize blockchain audit manager
if BLOCKCHAIN_AVAILABLE:
    try:
        blockchain_manager = create_audit_manager(network="testnet")
        print("✅ Blockchain audit manager initialized")
    except Exception as e:
        print(f"⚠️ Blockchain manager initialization failed: {str(e)}")
        blockchain_manager = None
else:
    blockchain_manager = None

# Initialize enhanced fraud detector
if FRAUD_DETECTOR_AVAILABLE:
    try:
        fraud_detector = EnhancedFraudDetector(blockchain_network="testnet")
        print("✅ Enhanced fraud detector initialized")
    except Exception as e:
        print(f"⚠️ Fraud detector initialization failed: {str(e)}")
        fraud_detector = None
else:
    fraud_detector = None

def get_sensitive_data(text):
    analysis_results = analyzer.analyze(text=text, entities=None, language="en")

    sensitive_data = {}
    

    for result in analysis_results:
        entity_text = text[result.start:result.end]  # Extract actual sensitive text
        if len(entity_text) <= 2:
            continue
        entity_label = result.entity_type  # Get entity label

        # Generate a secure token for the entity
        safe_token = generate_secure_token()

        # Get confidence score
        confidence_score = result.score
        if entity_label=="IN_PAN" and confidence_score<=0.7:
            continue
        # Store in dictionary
        else:
            sensitive_data[entity_text] = {
            "entity": entity_label,
            "safe_token": safe_token,
            "confidence_score": confidence_score
        }
    regex_sensitive_data = indian_specific_regex(text)

    # Merge the results
    sensitive_data.update(regex_sensitive_data)

    return sensitive_data
@app.route('/extract-sensitive-data', methods=['POST'])
def extract_and_store_sensitive_data(text):
    try:
        # Parse request data
       
        # Extract sensitive data
        sensitive_data = get_sensitive_data(text)

        # Store in Firestore
        store_sensitive_data_firestore(sensitive_data)

        return jsonify({"message": "Data saved successfully!", "sensitive_data": sensitive_data})

    except Exception as e:
        print("Error occurred:", str(e))  # Log the error
        return jsonify({"error": str(e)}), 500


def convert_np_floats(value):
    """Recursively converts numpy float32 values to Python float."""
    if isinstance(value, np.float32):
        return float(value)
    if isinstance(value, dict):
        return {k: convert_np_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [convert_np_floats(v) for v in value]
    return value

def store_sensitive_data_firestore(sensitive_data):
    try:
        print(f"Received sensitive data: {sensitive_data}")
        if not sensitive_data:
            print("No sensitive data to store.")
            return

        for entity_text, details in sensitive_data.items():
            safe_token = details.get("safe_token")

            if not safe_token:
                print(f"Skipping {entity_text} due to missing safe_token")
                continue

            cleaned_details = convert_np_floats(details)

            print(f"Storing entity: {entity_text}, Safe Token: {safe_token}")

            try:
                db.collection("tokens").document(safe_token).set({
                    "original_text": entity_text,
                    "entity": cleaned_details.get("entity"),
                    "confidence_score": cleaned_details.get("confidence_score")
                })
                print(f"✅ Stored {entity_text} successfully!")
            except Exception as firestore_error:
                print(f"❌ Firestore Error for {entity_text}: {firestore_error}")

    except Exception as e:
        print(f"Error storing data in Firestore: {e}")


def apply_blur(page, area):
    """Apply a blur effect on a specific area."""
    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
    img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.h, pix.w, pix.n)
    
    x0, y0, x1, y1 = map(int, [area.x0, area.y0, area.x1, area.y1])
    sub_img = img[y0:y1, x0:x1]
    
    # Apply Gaussian blur
    blurred = cv2.GaussianBlur(sub_img, (21, 21), 30)
    img[y0:y1, x0:x1] = blurred

    # Convert back to PDF
    pix.samples = img.tobytes()
    page.insert_image(area, pixmap=pix)
    
def apply_blur_on_image(image_path, area):
    """Apply a blur effect on a specific area in the image."""
    img = cv2.imread(image_path)
    
    x0, y0, x1, y1 = map(int, [area[0], area[1], area[2], area[3]])
    sub_img = img[y0:y1, x0:x1]
    
    # Apply Gaussian blur
    blurred = cv2.GaussianBlur(sub_img, (21, 21), 30)
    img[y0:y1, x0:x1] = blurred

    cv2.imwrite(image_path, img)
    
def redact_text_with_image(image_path, text, blur=False):
    """Redact or blur sensitive text in an image."""
    sensitive_data = get_sensitive_data(text)

    # Get bounding boxes of sensitive data
    for data in sensitive_data.keys():
        # Detect the bounding boxes for sensitive data using Tesseract
        boxes = pytesseract.image_to_boxes(Image.open(image_path))
        
        for box in boxes.splitlines():
            b = box.split()
            if b[0] == data:
                x, y, w, h = int(b[1]), int(b[2]), int(b[3]), int(b[4])

                if blur:
                    apply_blur_on_image(image_path, (x, y, w, h))
                else:
                    # Redact with black box
                    img = cv2.imread(image_path)
                    img[y:h, x:w] = COLOR_MASK
                    cv2.imwrite(image_path, img)


def redact_text_with_pymupdf(doc, blur=False):
    """Redact or blur sensitive text in a PDF."""
    for page in doc:
        page.wrap_contents()
        text = page.get_text("text")
        
        # Detect sensitive info
        sensitive_data = get_sensitive_data(text)

        for data in sensitive_data.keys():
            raw_areas = page.search_for(data)

            for area in raw_areas:
                extracted_text = page.get_text("text", clip=area).strip()
                if extracted_text == data:
                    if blur:
                        apply_blur(page, area)
                    else:
                        page.add_redact_annot(area, fill=color_map[COLOR_MASK])

        page.apply_redactions()

    return doc



def process_image(image_path, output_image_path, blur=False):
    """Complete process for images: Detect sensitive data, redact/blur, and save."""
    text = extract_text_from_image(image_path)
    
    # ✅ Redact or blur sensitive data in the image
    redact_text_with_image(image_path, text, blur=blur)
    
    # ✅ Save the processed image
    cv2.imwrite(output_image_path, cv2.imread(image_path))

    return output_image_path, text


def process_pdf(pdf_path, output_pdf, blur=False):
    """Complete process: Extract text, detect sensitive info, tokenize, redact/blur, and save."""
    text, doc = extract_text_from_pdf(pdf_path)

    # ✅ Redact or blur sensitive data in PDF
    redacted_doc = redact_text_with_pymupdf(doc, blur=blur)

    # ✅ Save the redacted/blurred PDF
    print(f"Saving redacted PDF to: {output_pdf}")

    redacted_doc.save(output_pdf)

    return output_pdf, text 

def get_token_map(text):
    """
    Get a mapping of detected entities with their original name and entity type.
    """
    analysis_results = analyzer.analyze(text=text, entities=None, language="en")
    
    token_map = {}
    for result in analysis_results:
        entity_text = text[result.start:result.end]  # Extract original entity text
        entity_label = result.entity_type  # Get entity type
        
        token_map[entity_text] = entity_label

    return token_map

@app.route("/process", methods=["POST"])
def process_file_endpoint():
    """Upload & process PDFs and images."""
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    
    if file.filename == '':
        return "No selected file", 400
    
    # Secure filename and save original file
    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(input_path)

    output_filename = "processed_" + filename
    output_path = os.path.join(app.config["PROCESSED_FOLDER"], output_filename)

    # Check file type & process accordingly
    if filename.lower().endswith('.pdf'):
        process_pdf(input_path, output_path, blur=False)  # Save processed PDF
    elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        process_image(input_path, output_path, blur=False)  # Save processed image
    else:
        return "Unsupported file format", 400

    # Redirect to preview page
    return redirect(url_for("process_file", filename=output_filename))



@app.route("/", methods=["GET"])
def dashboard():
    """Main dashboard with enhanced UI and fraud detection overview"""
    try:
        # Get system statistics
        stats = {
            "total_documents": get_document_count(),
            "fraud_detected": get_fraud_count(),
            "pii_protected": get_pii_count(),
            "blockchain_records": get_blockchain_count()
        }
        
        # Get recent activity
        recent_activity = get_recent_activity()
        
        return render_template("dashboard.html", 
                             stats=stats, 
                             recent_activity=recent_activity,
                             fraud_steps=get_fraud_detection_steps())
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        return render_template("dashboard.html", 
                             stats={"total_documents": 0, "fraud_detected": 0, "pii_protected": 0, "blockchain_records": 0},
                             recent_activity=[],
                             fraud_steps=get_fraud_detection_steps())

@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    """Enhanced upload interface"""
    if request.method == "POST":
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            return jsonify({
                "success": True,
                "filename": filename,
                "redirect_url": url_for("preview_file", filename=filename)
            })

    return render_template("upload.html")

@app.route("/preview/<filename>")
def preview_file(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    return render_template("preview.html", filename=filename)
@app.route("/process/<filename>")
def process_file(filename):
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    print(f"File path for upload: {file_path}")  # Debugging file path

    # Check if the file exists
    if not os.path.exists(file_path):
        return f"File {filename} not found in upload directory", 404

    if filename.lower().endswith(".pdf"):
        output_filename = "processed_" + filename  # Example: "processed_filename.pdf"
        output_path = os.path.join(app.config["PROCESSED_FOLDER"], output_filename)
        print(f"Saving processed PDF to: {output_path}")  # Debugging output path
        _, extracted_text = process_pdf(file_path, output_path)
    else:
        output_filename = "processed_" + filename  # Example: "processed_filename.png"
        output_path = os.path.join(app.config["PROCESSED_FOLDER"], output_filename)
        print(f"Saving processed image to: {output_path}")  # Debugging output path
        _, extracted_text = process_image(file_path, output_path)

    sensitive_data = get_sensitive_data(extracted_text)
    store_sensitive_data_firestore(sensitive_data)

    # Return the result page with the processed filename
    # print(sensitive_data)
    return render_template(
        "result.html",
        filename=output_filename,
        extracted_text=extracted_text,
        sensitive_data=sensitive_data,
    )

from flask import send_from_directory
@app.route("/download/<filename>")
def download_file(filename):
    """Allow user to download processed file."""
    file_path = os.path.join(app.config["PROCESSED_FOLDER"], filename)  # FIXED
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

# ===== BLOCKCHAIN AND ENHANCED FEATURES ROUTES =====

@app.route("/enhanced", methods=["GET"])
def enhanced_interface():
    """Serve the enhanced blockchain-enabled interface"""
    try:
        return render_template("../templates/enhanced_index.html")
    except Exception as e:
        print(f"Error serving enhanced interface: {str(e)}")
        return "Enhanced interface not available", 404

@app.route("/api/stacks/fees", methods=["GET"])
def get_stacks_fees():
    """Get current Stacks service fees"""
    try:
        if blockchain_manager:
            fees_result = blockchain_manager.get_service_fees()
            return jsonify(fees_result)
        else:
            # Return default fees if blockchain not available
            return jsonify({
                "success": True,
                "fees": {
                    "registration": {"display": "1.0 STX"},
                    "verification": {"display": "0.5 STX"},
                    "access": {"display": "0.25 STX"},
                    "premium_storage": {"display": "2.0 STX"}
                },
                "network": "testnet"
            })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/wallet/connect", methods=["POST"])
def connect_wallet():
    """Handle wallet connection requests"""
    try:
        data = request.get_json()
        wallet_type = data.get("wallet_type")
        wallet_address = data.get("wallet_address")
        
        if not wallet_type or not wallet_address:
            return jsonify({
                "success": False,
                "error": "Missing wallet type or address"
            }), 400
        
        # Store wallet connection (in production, you'd validate the wallet)
        # For now, just acknowledge the connection
        return jsonify({
            "success": True,
            "message": f"Wallet {wallet_type} connected successfully",
            "wallet_address": wallet_address,
            "network": "testnet" if wallet_type == "leather" else "ethereum"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    """Handle Google authentication"""
    try:
        data = request.get_json()
        google_token = data.get("google_token")
        
        if not google_token:
            return jsonify({
                "success": False,
                "error": "Missing Google token"
            }), 400
        
        # In production, verify the Google token here
        # For now, just acknowledge the authentication
        return jsonify({
            "success": True,
            "message": "Google authentication successful"
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/analyze-fraud", methods=["POST"])
def analyze_fraud():
    """Analyze document for fraud using enhanced fraud detector"""
    try:
        if not fraud_detector:
            return jsonify({
                "success": False,
                "error": "Fraud detector not available"
            }), 503
        
        if 'file' not in request.files:
            return jsonify({
                "success": False,
                "error": "No file provided"
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected"
            }), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"temp_fraud_{filename}")
        file.save(temp_path)
        
        # Prepare metadata
        metadata = {
            "filename": filename,
            "upload_time": datetime.now().isoformat(),
            "file_size": os.path.getsize(temp_path),
            "analysis_type": "fraud_detection"
        }
        
        # Analyze for fraud
        fraud_result = fraud_detector.analyze_document(temp_path, metadata)
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        # Return results
        return jsonify({
            "success": True,
            "fraud_analysis": {
                "fraud_probability": fraud_result.fraud_probability,
                "risk_level": fraud_result.risk_level,
                "confidence_score": fraud_result.confidence_score,
                "suspicious_patterns": fraud_result.suspicious_patterns,
                "blockchain_hash": fraud_result.blockchain_hash,
                "audit_trail_id": fraud_result.audit_trail_id,
                "recommendations": fraud_result.analysis_details.get("recommendations", [])
            }
        })
        
    except Exception as e:
        print(f"Fraud analysis error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/blockchain/register", methods=["POST"])
def register_on_blockchain():
    """Register document on blockchain"""
    try:
        if not blockchain_manager:
            return jsonify({
                "success": False,
                "error": "Blockchain manager not available"
            }), 503
        
        if 'file' not in request.files:
            return jsonify({
                "success": False,
                "error": "No file provided"
            }), 400
        
        file = request.files['file']
        metadata = request.form.to_dict()
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"temp_blockchain_{filename}")
        file.save(temp_path)
        
        # Read file content for hashing
        with open(temp_path, 'rb') as f:
            file_content = f.read()
        
        # Prepare metadata with timestamp
        blockchain_metadata = {
            **metadata,
            "filename": filename,
            "file_size": len(file_content),
            "registration_time": datetime.now().isoformat(),
            "network": "testnet"
        }
        
        # Generate document hash
        document_hash = blockchain_manager.generate_document_hash(file_content, blockchain_metadata)
        
        # Register on blockchain
        registration_result = blockchain_manager.register_document(
            document_hash,
            blockchain_metadata,
            metadata.get("wallet_address")
        )
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return jsonify(registration_result)
        
    except Exception as e:
        print(f"Blockchain registration error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/blockchain/verify/<document_hash>", methods=["GET"])
def verify_on_blockchain(document_hash):
    """Verify document on blockchain"""
    try:
        if not blockchain_manager:
            return jsonify({
                "success": False,
                "error": "Blockchain manager not available"
            }), 503
        
        verification_result = blockchain_manager.verify_document(document_hash)
        return jsonify(verification_result)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/audit-trail/<document_hash>", methods=["GET"])
def get_audit_trail(document_hash):
    """Get audit trail for document"""
    try:
        if not blockchain_manager:
            return jsonify({
                "success": False,
                "error": "Blockchain manager not available"
            }), 503
        
        history_result = blockchain_manager.get_document_history(document_hash)
        return jsonify(history_result)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ===== ENHANCED FRAUD DETECTION METHODS =====

def get_fraud_detection_steps():
    """Return the 5-step fraud detection process"""
    return [
        {
            "step": 1,
            "title": "Document Intake & Analysis",
            "description": "Initial document upload and format validation",
            "details": "Secure file upload, format verification, and preliminary structure analysis",
            "icon": "fas fa-upload",
            "color": "#3B82F6"
        },
        {
            "step": 2,
            "title": "Metadata Examination",
            "description": "Deep analysis of document metadata and digital fingerprints",
            "details": "Creation dates, modification history, author information, and tool signatures",
            "icon": "fas fa-search",
            "color": "#8B5CF6"
        },
        {
            "step": 3,
            "title": "Content Consistency Check",
            "description": "AI-powered analysis of document content and structure",
            "details": "Font analysis, layout consistency, text coherence, and logical flow validation",
            "icon": "fas fa-brain",
            "color": "#10B981"
        },
        {
            "step": 4,
            "title": "Digital Forensics Scan",
            "description": "Advanced forensic analysis for manipulation detection",
            "details": "Image splicing detection, copy-paste analysis, and compression artifact examination",
            "icon": "fas fa-microscope",
            "color": "#F59E0B"
        },
        {
            "step": 5,
            "title": "Risk Assessment & Blockchain Audit",
            "description": "Final risk scoring and immutable audit trail creation",
            "details": "Fraud probability calculation, risk level assignment, and blockchain registration",
            "icon": "fas fa-shield-alt",
            "color": "#EF4444"
        }
    ]

def analyze_document_fraud_steps(file_path, filename):
    """Enhanced fraud detection with 5-step process tracking"""
    try:
        fraud_analysis = {
            "filename": filename,
            "analysis_id": f"FA_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "steps": [],
            "overall_result": {}
        }
        
        # Step 1: Document Intake & Analysis
        step1_result = perform_intake_analysis(file_path)
        fraud_analysis["steps"].append({
            "step": 1,
            "status": "completed",
            "result": step1_result,
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 2: Metadata Examination
        step2_result = perform_metadata_analysis(file_path)
        fraud_analysis["steps"].append({
            "step": 2,
            "status": "completed",
            "result": step2_result,
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 3: Content Consistency Check
        step3_result = perform_content_analysis(file_path)
        fraud_analysis["steps"].append({
            "step": 3,
            "status": "completed",
            "result": step3_result,
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 4: Digital Forensics Scan
        step4_result = perform_forensics_analysis(file_path)
        fraud_analysis["steps"].append({
            "step": 4,
            "status": "completed",
            "result": step4_result,
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 5: Risk Assessment & Blockchain Audit
        step5_result = perform_risk_assessment(fraud_analysis["steps"])
        fraud_analysis["steps"].append({
            "step": 5,
            "status": "completed",
            "result": step5_result,
            "timestamp": datetime.now().isoformat()
        })
        
        # Calculate overall fraud probability
        fraud_probability = calculate_overall_fraud_probability(fraud_analysis["steps"])
        risk_level = determine_risk_level(fraud_probability)
        
        fraud_analysis["overall_result"] = {
            "fraud_probability": fraud_probability,
            "risk_level": risk_level,
            "recommendation": get_recommendation(risk_level),
            "confidence_score": calculate_confidence_score(fraud_analysis["steps"])
        }
        
        return fraud_analysis
        
    except Exception as e:
        logger.error(f"Error in fraud analysis: {str(e)}")
        return {
            "error": str(e),
            "filename": filename,
            "analysis_id": "ERROR"
        }

def perform_intake_analysis(file_path):
    """Step 1: Document Intake & Analysis"""
    import os
    file_size = os.path.getsize(file_path)
    file_ext = os.path.splitext(file_path)[1].lower()
    
    # Simulate intake analysis
    return {
        "file_size_mb": round(file_size / (1024*1024), 2),
        "file_format": file_ext,
        "format_valid": file_ext in ['.pdf', '.png', '.jpg', '.jpeg'],
        "size_suspicious": file_size > 10*1024*1024 or file_size < 1024,
        "structure_score": np.random.uniform(0.7, 0.95),
        "anomalies_detected": []
    }

def perform_metadata_analysis(file_path):
    """Step 2: Metadata Examination"""
    # Simulate metadata analysis
    return {
        "creation_date_valid": np.random.choice([True, False], p=[0.8, 0.2]),
        "modification_history": np.random.randint(1, 5),
        "author_consistent": np.random.choice([True, False], p=[0.9, 0.1]),
        "tool_signatures": ["Adobe Acrobat", "Microsoft Word"],
        "metadata_score": np.random.uniform(0.6, 0.9),
        "suspicious_flags": []
    }

def perform_content_analysis(file_path):
    """Step 3: Content Consistency Check"""
    # Simulate content analysis
    return {
        "font_consistency": np.random.uniform(0.7, 0.95),
        "layout_regularity": np.random.uniform(0.8, 0.95),
        "text_coherence": np.random.uniform(0.6, 0.9),
        "logical_flow": np.random.uniform(0.7, 0.9),
        "content_score": np.random.uniform(0.7, 0.9),
        "inconsistencies": []
    }

def perform_forensics_analysis(file_path):
    """Step 4: Digital Forensics Scan"""
    # Simulate forensics analysis
    return {
        "image_tampering": np.random.uniform(0.1, 0.3),
        "copy_paste_detected": np.random.choice([True, False], p=[0.2, 0.8]),
        "compression_artifacts": np.random.uniform(0.1, 0.4),
        "pixel_analysis_score": np.random.uniform(0.7, 0.95),
        "forensics_score": np.random.uniform(0.6, 0.9),
        "manipulation_indicators": []
    }

def perform_risk_assessment(steps_results):
    """Step 5: Risk Assessment & Blockchain Audit"""
    # Simulate risk assessment
    return {
        "risk_factors_identified": np.random.randint(0, 3),
        "blockchain_registered": BLOCKCHAIN_AVAILABLE,
        "audit_trail_created": True,
        "assessment_score": np.random.uniform(0.7, 0.95),
        "recommendations": [
            "Document appears legitimate",
            "No significant fraud indicators detected",
            "Proceed with normal processing"
        ]
    }

def calculate_overall_fraud_probability(steps_results):
    """Calculate overall fraud probability from all steps"""
    scores = []
    for step in steps_results:
        if 'result' in step and isinstance(step['result'], dict):
            for key, value in step['result'].items():
                if '_score' in key and isinstance(value, (int, float)):
                    scores.append(1 - value)  # Convert good scores to fraud probability
    
    if scores:
        return max(0.0, min(1.0, np.mean(scores)))
    return 0.2  # Default low fraud probability

def determine_risk_level(fraud_probability):
    """Determine risk level based on fraud probability"""
    if fraud_probability < 0.3:
        return "LOW"
    elif fraud_probability < 0.6:
        return "MEDIUM"
    else:
        return "HIGH"

def get_recommendation(risk_level):
    """Get recommendation based on risk level"""
    recommendations = {
        "LOW": "Document appears legitimate. Proceed with normal processing.",
        "MEDIUM": "Some suspicious indicators detected. Manual review recommended.",
        "HIGH": "High fraud probability detected. Immediate investigation required."
    }
    return recommendations.get(risk_level, "Unknown risk level")

def calculate_confidence_score(steps_results):
    """Calculate confidence score for the analysis"""
    return np.random.uniform(0.85, 0.98)

# ===== DASHBOARD UTILITY FUNCTIONS =====

def get_document_count():
    """Get total number of processed documents"""
    try:
        return len([f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.endswith(('.pdf', '.png', '.jpg', '.jpeg'))])
    except:
        return 0

def get_fraud_count():
    """Get number of fraudulent documents detected"""
    # Simulate fraud count
    return np.random.randint(5, 25)

def get_pii_count():
    """Get number of PII entities protected"""
    # Simulate PII count
    return np.random.randint(100, 500)

def get_blockchain_count():
    """Get number of blockchain records"""
    # Simulate blockchain count
    return np.random.randint(50, 200)

def get_recent_activity():
    """Get recent activity data"""
    activities = [
        {"type": "Document Processed", "file": "invoice_2024.pdf", "time": "2 hours ago", "status": "success"},
        {"type": "Fraud Detected", "file": "suspicious_doc.pdf", "time": "4 hours ago", "status": "warning"},
        {"type": "PII Redacted", "file": "personal_info.png", "time": "6 hours ago", "status": "success"},
        {"type": "Blockchain Record", "file": "contract_2024.pdf", "time": "8 hours ago", "status": "success"}
    ]
    return activities

# ===== ENHANCED LEATHER WALLET & STACKS TRANSACTION ROUTES =====

@app.route("/api/wallet/leather/connect", methods=["POST"])
def connect_leather_wallet():
    """Enhanced Leather wallet connection with Stacks Connect integration"""
    try:
        data = request.get_json()
        auth_data = data.get('authData', {})
        user_session = data.get('userSession', {})
        wallet_address = data.get('wallet_address')
        network = data.get('network', 'testnet')
        
        # Extract user data from Stacks authentication
        user_data = user_session.get('userData', {})
        profile = user_data.get('profile', {})
        
        # Get Stacks address from profile or use provided address
        if profile and 'stxAddress' in profile:
            stx_addresses = profile.get('stxAddress', {})
            wallet_address = stx_addresses.get('testnet') or stx_addresses.get('mainnet')
        
        if not wallet_address:
            return jsonify({
                'success': False,
                'error': 'No Stacks address found in authentication data'
            }), 400
        
        # Validate Stacks address format
        if not (wallet_address.startswith('ST') or wallet_address.startswith('SP')):
            return jsonify({
                'success': False,
                'error': 'Invalid Stacks address format'
            }), 400
        
        # Store wallet connection in session or database
        wallet_info = {
            'type': 'leather',
            'address': wallet_address,
            'network': network,
            'connected_at': datetime.now().isoformat(),
            'profile': profile
        }
        
        # Store in Firebase if available
        if FIREBASE_AVAILABLE and db:
            try:
                db.collection('wallet_connections').document(wallet_address).set(wallet_info)
                print(f"✅ Leather wallet connection stored: {wallet_address[:8]}...")
            except Exception as e:
                print(f"⚠️ Failed to store wallet connection: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': 'Leather wallet connected successfully',
            'wallet': {
                'type': 'leather',
                'address': wallet_address,
                'network': network
            },
            'user': {
                'name': profile.get('name', 'Stacks User'),
                'stxAddress': wallet_address
            }
        })
        
    except Exception as e:
        print(f"Leather wallet connection error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/stacks/transaction/prepare", methods=["POST"])
def prepare_stacks_transaction():
    """Prepare Stacks transaction for document processing fees"""
    try:
        data = request.get_json()
        transaction_type = data.get('transaction_type')  # 'registration', 'verification', etc.
        amount_stx = data.get('amount_stx', 1.0)  # Amount in STX
        wallet_address = data.get('wallet_address')
        document_hash = data.get('document_hash')
        
        if not all([transaction_type, wallet_address]):
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            }), 400
        
        # Convert STX to microSTX (1 STX = 1,000,000 microSTX)
        amount_microstx = int(amount_stx * 1_000_000)
        
        # Define service fees
        service_fees = {
            'registration': 1.0,
            'verification': 0.5,
            'access': 0.25,
            'premium_storage': 2.0
        }
        
        fee_amount = service_fees.get(transaction_type, 1.0)
        fee_microstx = int(fee_amount * 1_000_000)
        
        # Prepare transaction data
        transaction_data = {
            'transaction_type': transaction_type,
            'amount_microstx': amount_microstx or fee_microstx,
            'amount_stx': amount_stx or fee_amount,
            'sender': wallet_address,
            'recipient': 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',  # Contract address
            'memo': f'SecuredDoc {transaction_type}: {document_hash[:16] if document_hash else "doc"}',
            'network': 'testnet',
            'fee': 1000,  # Transaction fee in microSTX
            'prepared_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'transaction_data': transaction_data,
            'message': f'Transaction prepared for {transaction_type}'
        })
        
    except Exception as e:
        print(f"Transaction preparation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/stacks/transaction/submit", methods=["POST"])
def submit_stacks_transaction():
    """Record submitted Stacks transaction"""
    try:
        data = request.get_json()
        tx_id = data.get('tx_id')
        transaction_type = data.get('transaction_type')
        amount_stx = data.get('amount_stx')
        wallet_address = data.get('wallet_address')
        document_hash = data.get('document_hash')
        
        if not tx_id:
            return jsonify({
                'success': False,
                'error': 'Missing transaction ID'
            }), 400
        
        # Create transaction record
        transaction_record = {
            'tx_id': tx_id,
            'transaction_type': transaction_type,
            'amount_stx': amount_stx,
            'wallet_address': wallet_address,
            'document_hash': document_hash,
            'status': 'pending',
            'submitted_at': datetime.now().isoformat(),
            'network': 'testnet'
        }
        
        # Store in Firebase if available
        if FIREBASE_AVAILABLE and db:
            try:
                db.collection('stacks_transactions').document(tx_id).set(transaction_record)
                print(f"✅ Transaction recorded: {tx_id}")
            except Exception as e:
                print(f"⚠️ Failed to store transaction: {str(e)}")
        
        return jsonify({
            'success': True,
            'tx_id': tx_id,
            'message': 'Transaction submitted successfully',
            'explorer_url': f'https://explorer.stacks.co/txid/{tx_id}?chain=testnet'
        })
        
    except Exception as e:
        print(f"Transaction submission error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/stacks/transaction/status/<tx_id>", methods=["GET"])
def get_transaction_status(tx_id):
    """Get Stacks transaction status"""
    try:
        # In a real implementation, you would query the Stacks blockchain
        # For demo purposes, we'll simulate the status
        
        # Try to get from Firebase first
        transaction_data = None
        if FIREBASE_AVAILABLE and db:
            try:
                doc = db.collection('stacks_transactions').document(tx_id).get()
                if doc.exists:
                    transaction_data = doc.to_dict()
            except Exception as e:
                print(f"⚠️ Failed to fetch transaction: {str(e)}")
        
        # Simulate transaction status
        status_options = ['pending', 'confirmed', 'failed']
        status = np.random.choice(status_options, p=[0.3, 0.6, 0.1])
        
        result = {
            'tx_id': tx_id,
            'status': status,
            'block_height': np.random.randint(100000, 200000) if status == 'confirmed' else None,
            'confirmations': np.random.randint(1, 10) if status == 'confirmed' else 0,
            'fee_paid': '0.001 STX',
            'explorer_url': f'https://explorer.stacks.co/txid/{tx_id}?chain=testnet'
        }
        
        if transaction_data:
            result.update(transaction_data)
        
        return jsonify({
            'success': True,
            'transaction': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/stacks/fees", methods=["GET"])
def get_stacks_service_fees():
    """Get current Stacks service fees"""
    try:
        fees = {
            'registration': {
                'amount_stx': 1.0,
                'amount_microstx': 1_000_000,
                'display': '1.0 STX',
                'description': 'Document registration on blockchain'
            },
            'verification': {
                'amount_stx': 0.5,
                'amount_microstx': 500_000,
                'display': '0.5 STX',
                'description': 'Document verification service'
            },
            'access': {
                'amount_stx': 0.25,
                'amount_microstx': 250_000,
                'display': '0.25 STX',
                'description': 'Access grant for document'
            },
            'premium_storage': {
                'amount_stx': 2.0,
                'amount_microstx': 2_000_000,
                'display': '2.0 STX',
                'description': 'Premium storage with enhanced features'
            }
        }
        
        return jsonify({
            'success': True,
            'fees': fees,
            'network': 'testnet',
            'updated_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/api/document/process-with-payment", methods=["POST"])
def process_document_with_payment():
    """Process document with Stacks payment integration"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        tx_id = request.form.get('tx_id')  # Stacks transaction ID
        wallet_address = request.form.get('wallet_address')
        service_type = request.form.get('service_type', 'registration')
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Verify payment transaction (in production, verify on-chain)
        if tx_id:
            print(f"✅ Processing with payment: {tx_id}")
        
        # Save and process file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
        file.save(file_path)
        
        # Process document based on file type
        extracted_text = ""
        if filename.lower().endswith('.pdf'):
            output_filename = f"processed_{unique_filename}"
            output_path = os.path.join(app.config["OUTPUT_FOLDER"], output_filename)
            _, extracted_text = process_pdf(file_path, output_path)
        elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            output_filename = f"processed_{unique_filename}"
            output_path = os.path.join(app.config["OUTPUT_FOLDER"], output_filename)
            _, extracted_text = process_image(file_path, output_path)
        
        # Extract and store sensitive data
        sensitive_data = get_sensitive_data(extracted_text)
        if sensitive_data:
            store_sensitive_data_firestore(sensitive_data)
        
        # Enhanced fraud detection if enabled
        fraud_analysis = None
        if service_type in ['premium_storage', 'verification']:
            fraud_analysis = analyze_document_fraud_steps(file_path, filename)
        
        # Create comprehensive result
        result = {
            'success': True,
            'filename': unique_filename,
            'service_type': service_type,
            'payment_tx_id': tx_id,
            'wallet_address': wallet_address,
            'extracted_text': extracted_text,
            'pii_detection': {
                'sensitive_data': sensitive_data,
                'pii_count': len(sensitive_data),
                'entities_found': list(set([data['entity'] for data in sensitive_data.values()]))
            },
            'fraud_analysis': fraud_analysis,
            'blockchain_registered': bool(tx_id),
            'processed_at': datetime.now().isoformat()
        }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Document processing with payment error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ===== ENHANCED API ROUTES =====

@app.route("/api/fraud-analysis", methods=["POST"])
def enhanced_fraud_analysis():
    """Enhanced fraud analysis API with 5-step process"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"temp_analysis_{filename}")
        file.save(temp_path)
        
        # Perform enhanced fraud analysis
        analysis_result = analyze_document_fraud_steps(temp_path, filename)
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return jsonify({
            "success": True,
            "analysis": analysis_result,
            "fraud_steps": get_fraud_detection_steps()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        stats = {
            "total_documents": get_document_count(),
            "fraud_detected": get_fraud_count(),
            "pii_protected": get_pii_count(),
            "blockchain_records": get_blockchain_count(),
            "recent_activity": get_recent_activity()
        }
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    try:
        app.config['DEBUG'] = True
        print("🚀 Starting SecureDoc Enhanced Server...")
        print("📊 Dashboard available at: http://localhost:5001/")
        print("📤 Upload interface at: http://localhost:5001/upload")
        print("🔍 Fraud detection API: http://localhost:5001/api/fraud-analysis")
        app.run(debug=True, port=5001, host='0.0.0.0')
    except Exception as e:
        print(f"Error starting server: {str(e)}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...") # This keeps the window open

# if __name__ == "__main__":
#     # ✅ Sample text to test the model
#     file_path = r"D:\CodeFest(tokenization)\Codefest_Token\Codefest_Token\image.png"
    
#     # Process PDF or image based on the file type
#     if file_path.lower().endswith(".pdf"):
#         print(f"\n🔹 Processing PDF: {file_path}")
#         processed_pdf, extracted_text = process_pdf(file_path, "processed_output.pdf")

#     elif file_path.lower().endswith((".png", ".jpg", ".jpeg")):
#         print(f"\n🔹 Processing Image: {file_path}")
#         processed_image, extracted_text = process_image(file_path, "processed_output.png")

#     else:
#         print("❌ Unsupported file type! Please provide a PDF or image.")
#         exit(1)

#     # ✅ Get token-wise entity mapping
#     entity_map = get_token_map(extracted_text)

#     # ✅ Get sensitive data with secure tokens and confidence scores
#     sensitive_data = get_sensitive_data(extracted_text)

#     # ✅ Print the results
#     print("\n📌 Entity Map with Secure Tokens and Confidence Scores:")
#     if sensitive_data:
#         for token, details in sensitive_data.items():
#             # Extract the safe token and confidence score
#             safe_token = details.get("safe_token")
#             confidence_score = details.get("confidence_score")
#             entity_type = details.get("entity")
#             if entity_type=="IN_PAN" and confidence_score<=0.7:
#                 continue
#             # Print the token, entity, generated secure token, and confidence score
#             print(f"Token: {token} -> Entity: {entity_type} -> Safe Token: {safe_token} -> Confidence Score: {confidence_score:.2f}")
#     else:
#         print("No sensitive entities found in the document.")
