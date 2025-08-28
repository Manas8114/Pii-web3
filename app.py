"""
SecuredDoc - Main Flask Application
Blockchain-powered Document Security and Fraud Detection System
"""

from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, session, flash
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime, timedelta
import secrets

# Import our existing modules
from enhanced_fraud_detector import EnhancedFraudDetector, FraudDetectionResult
from Models.blockchain_audit import BlockchainAuditManager

# Import document processing functionality
import pytesseract
from PIL import Image
from transformers import pipeline
import fitz
import spacy
import cv2
import numpy as np
from presidio_analyzer import AnalyzerEngine, EntityRecognizer, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.nlp_engine import NlpArtifacts
from typing import List
import re
import uuid

# Firebase integration
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    
    cred = credentials.Certificate('Models/serviceAccountKey.json')
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    FIREBASE_AVAILABLE = True
    print("✅ Firebase initialized successfully")
except Exception as e:
    print(f"⚠️ Firebase initialization failed: {str(e)}")
    db = None
    FIREBASE_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.secret_key = secrets.token_hex(16)
app.permanent_session_lifetime = timedelta(hours=2)

# Directory configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
RESULTS_FOLDER = 'enhanced_results'
STATIC_FOLDER = 'static'

# Ensure directories exist
for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER, RESULTS_FOLDER, STATIC_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config.update({
    'UPLOAD_FOLDER': UPLOAD_FOLDER,
    'OUTPUT_FOLDER': OUTPUT_FOLDER,
    'RESULTS_FOLDER': RESULTS_FOLDER,
    'MAX_CONTENT_LENGTH': 50 * 1024 * 1024,  # 50MB max file size
})

# Initialize components
fraud_detector = EnhancedFraudDetector(blockchain_network="testnet")
blockchain_manager = BlockchainAuditManager(network="testnet")

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==================== DOCUMENT PROCESSING FUNCTIONS ====================

# Initialize NLP models with error handling
def load_spacy_model():
    """Load spacy model with fallback if not available"""
    try:
        # Try to load the model first
        nlp = spacy.load("en_core_web_sm")
        print("✅ Spacy model loaded successfully")
        return nlp
    except OSError:
        print("⚠️ Spacy model not found. To install it manually, run:")
        print("   python -m spacy download en_core_web_sm")
        print("📝 Continuing with basic text processing (PII detection will still work)")
        return None
    except Exception as e:
        print(f"⚠️ Error loading spacy model: {str(e)}")
        print("📝 Continuing with basic text processing")
        return None

# Load the spacy model (non-blocking)
nlp = load_spacy_model()

# Install command for manual setup
print("\n💡 To enable advanced NLP features, install spaCy model manually:")
print("   python -m spacy download en_core_web_sm")
print("   Then restart the application\n")

# Initialize transformers model with error handling
try:
    transformers_model = pipeline(
        "token-classification",
        model="dbmdz/bert-large-cased-finetuned-conll03-english",
        aggregation_strategy="average",
        ignore_labels=["O", "MISC"]
    )
except Exception as e:
    print(f"⚠️ Transformers model not available: {str(e)}")
    transformers_model = None

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

    def analyze(self, text: str, entities: List[str] = None, nlp_artifacts=None) -> List[RecognizerResult]:
        if not self.pipeline:
            return []
        
        results = []
        try:
            predicted_entities = self.pipeline(text)
            for e in predicted_entities:
                converted_entity = self.label2presidio.get(e["entity_group"], None)
                if converted_entity and (entities is None or converted_entity in entities):
                    results.append(RecognizerResult(entity_type=converted_entity, start=e["start"], end=e["end"], score=e["score"]))
        except Exception as e:
            print(f"Error in TransformersRecognizer: {str(e)}")
        
        return results

# Initialize Presidio components
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Add custom recognizer if available
if transformers_model:
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

def generate_secure_token():
    """Generate a unique secure token"""
    return str(uuid.uuid4())

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF."""
    doc = fitz.open(pdf_path)
    text = "\n".join(page.get_text("text") for page in doc)
    return text, doc

def extract_text_from_image(image_path):
    """Extract text from image using Tesseract OCR."""
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text
    except Exception as e:
        print(f"Error extracting text from image: {str(e)}")
        return ""

def indian_specific_regex(text):
    """Returns additional sensitive data based on Indian-specific regex patterns"""
    regex_patterns = {
        "IN_PAN": r"\b[A-Z]{5}\d{4}[A-Z]{1}\b",  
        "IN_AADHAAR": r"\b\d{4} \d{4} \d{4}\b", 
        "IN_PHONE": r"\b(?:\+91|91)?\d{10}\b",  
        "IN_PHONE_WITHOUT_CODE": r"\b[6789]\d{9}\b",
    }
    
    sensitive_data = {}
    
    for entity_name, pattern in regex_patterns.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            entity_text = match.group(0)
            safe_token = generate_secure_token()
            sensitive_data[entity_text] = {
                "entity": entity_name,
                "safe_token": safe_token,
                "confidence_score": 1.0
            }
    
    return sensitive_data

def get_sensitive_data(text):
    """Extract sensitive data using Presidio and regex patterns"""
    try:
        analysis_results = analyzer.analyze(text=text, entities=None, language="en")
    except Exception as e:
        print(f"Error in Presidio analysis: {str(e)}")
        analysis_results = []

    sensitive_data = {}
    
    for result in analysis_results:
        entity_text = text[result.start:result.end]
        if len(entity_text) <= 2:
            continue
        
        entity_label = result.entity_type
        safe_token = generate_secure_token()
        confidence_score = result.score
        
        if entity_label == "IN_PAN" and confidence_score <= 0.7:
            continue
            
        sensitive_data[entity_text] = {
            "entity": entity_label,
            "safe_token": safe_token,
            "confidence_score": confidence_score
        }
    
    # Add regex-based detection
    regex_sensitive_data = indian_specific_regex(text)
    sensitive_data.update(regex_sensitive_data)
    
    return sensitive_data

def convert_np_floats(value):
    """Recursively converts numpy float32/64 and other non-serializable values to Python types."""
    if isinstance(value, (np.float32, np.float64)):
        return float(value)
    if isinstance(value, (np.int32, np.int64)):
        return int(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, dict):
        return {k: convert_np_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [convert_np_floats(v) for v in value]
    if hasattr(value, 'item'):  # numpy scalar
        return value.item()
    return value

def store_sensitive_data_firestore(sensitive_data):
    """Store sensitive data in Firestore using batch operations for better performance"""
    if not FIREBASE_AVAILABLE or not db:
        print("⚠️ Firebase not available, skipping data storage")
        return
    
    try:
        if not sensitive_data:
            return

        # Use batch operations for better performance
        batch = db.batch()
        batch_count = 0
        successful_stores = 0
        
        for entity_text, details in sensitive_data.items():
            safe_token = details.get("safe_token")
            if not safe_token:
                continue

            cleaned_details = convert_np_floats(details)
            
            # Add to batch
            doc_ref = db.collection("tokens").document(safe_token)
            batch.set(doc_ref, {
                "original_text": entity_text,
                "entity": cleaned_details.get("entity"),
                "confidence_score": cleaned_details.get("confidence_score"),
                "timestamp": datetime.now().isoformat()
            })
            
            batch_count += 1
            successful_stores += 1
            
            # Commit batch when it reaches 500 operations (Firestore limit)
            if batch_count >= 500:
                batch.commit()
                batch = db.batch()
                batch_count = 0
        
        # Commit remaining operations
        if batch_count > 0:
            batch.commit()
            
        print(f"✅ Successfully stored {successful_stores} PII entities in Firebase")

    except Exception as e:
        print(f"❌ Error storing data in Firestore: {e}")

def redact_text_with_pymupdf(doc, blur=False):
    """Redact or blur sensitive text in a PDF."""
    for page in doc:
        page.wrap_contents()
        text = page.get_text("text")
        
        sensitive_data = get_sensitive_data(text)
        
        for data in sensitive_data.keys():
            raw_areas = page.search_for(data)
            for area in raw_areas:
                extracted_text = page.get_text("text", clip=area).strip()
                if extracted_text == data:
                    if blur:
                        # For simplicity, we'll use redaction instead of blur for now
                        page.add_redact_annot(area, fill=color_map[COLOR_MASK])
                    else:
                        page.add_redact_annot(area, fill=color_map[COLOR_MASK])
        
        page.apply_redactions()
    
    return doc

def process_pdf_document(pdf_path, output_pdf, blur=False):
    """Complete process: Extract text, detect sensitive info, redact, and save."""
    text, doc = extract_text_from_pdf(pdf_path)
    
    # Redact sensitive data in PDF
    redacted_doc = redact_text_with_pymupdf(doc, blur=blur)
    
    # Save the redacted PDF
    redacted_doc.save(output_pdf)
    
    return output_pdf, text

def process_image_document(image_path, output_image_path, blur=False):
    """Complete process for images: Detect sensitive data, redact, and save."""
    text = extract_text_from_image(image_path)
    
    # For now, just copy the image (redaction would require more complex OCR processing)
    try:
        img = cv2.imread(image_path)
        cv2.imwrite(output_image_path, img)
    except Exception as e:
        print(f"Error processing image: {str(e)}")
    
    return output_image_path, text

# ==================== ROUTES ====================

@app.route('/')
def home():
    """Landing page explaining the system and problem statement"""
    return render_template('home.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard with document processing functionality"""
    # Check if user is authenticated (for demo purposes, we'll skip strict auth)
    return render_template('dashboard.html')

@app.route('/login')
def login_page():
    """Login page with wallet connection and authentication"""
    return render_template('login.html')

@app.route('/auth')
def auth():
    """Authentication page (enhanced functionality)"""
    return render_template('enhanced_index.html')

@app.route('/process', methods=['POST'])
def process_document():
    """Process uploaded document with PII detection, fraud analysis, and blockchain registration"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'File type not allowed'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Get processing options
        enable_blockchain = request.form.get('enableBlockchain', 'true') == 'true'
        enable_fraud_detection = request.form.get('enableFraudDetection', 'true') == 'true'
        enable_audit_trail = request.form.get('enableAuditTrail', 'true') == 'true'
        
        logger.info(f"Processing document: {unique_filename}")
        
        # Step 1: Extract text and process document
        extracted_text = ""
        processed_file_path = None
        
        try:
            if filename.lower().endswith('.pdf'):
                # Process PDF
                output_filename = f"processed_{unique_filename}"
                processed_file_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
                _, extracted_text = process_pdf_document(file_path, processed_file_path)
            elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                # Process Image
                output_filename = f"processed_{unique_filename}"
                processed_file_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
                _, extracted_text = process_image_document(file_path, processed_file_path)
            else:
                # For other files, just extract text
                extracted_text = "File processing not supported for this format"
        except Exception as e:
            logger.error(f"Document processing error: {str(e)}")
            extracted_text = f"Error processing document: {str(e)}"
        
        # Step 2: PII Detection
        sensitive_data = get_sensitive_data(extracted_text) if extracted_text else {}
        
        # Store sensitive data in Firebase
        if sensitive_data:
            store_sensitive_data_firestore(sensitive_data)
        
        # Step 3: Enhanced Fraud Detection
        fraud_result = None
        if enable_fraud_detection:
            try:
                metadata = {
                    'filename': filename,
                    'upload_timestamp': datetime.now().isoformat(),
                    'file_size': os.path.getsize(file_path),
                    'user_id': session.get('user_id', 'anonymous'),
                    'extracted_text_length': len(extracted_text),
                    'pii_count': len(sensitive_data)
                }
                
                fraud_result = fraud_detector.analyze_document(file_path, metadata)
            except Exception as e:
                logger.error(f"Fraud detection error: {str(e)}")
        
        # Step 4: Blockchain Registration
        blockchain_result = None
        if enable_blockchain and fraud_result:
            try:
                blockchain_metadata = {
                    'filename': filename,
                    'processing_timestamp': datetime.now().isoformat(),
                    'pii_detected': len(sensitive_data),
                    'fraud_risk_level': fraud_result.risk_level,
                    'fraud_probability': fraud_result.fraud_probability
                }
                
                blockchain_result = blockchain_manager.register_document(
                    fraud_result.blockchain_hash or "fallback_hash", 
                    blockchain_metadata
                )
            except Exception as e:
                logger.error(f"Blockchain registration error: {str(e)}")
        
        # Step 5: Prepare comprehensive results
        results = {
            'success': True,
            'filename': unique_filename,
            'processed_filename': output_filename if processed_file_path else None,
            'timestamp': datetime.now().isoformat(),
            'extracted_text': extracted_text,
            'pii_detection': {
                'sensitive_data': sensitive_data,
                'pii_count': len(sensitive_data),
                'entities_found': list(set([data['entity'] for data in sensitive_data.values()]))
            },
            'fraud_detection': {
                'fraud_probability': fraud_result.fraud_probability if fraud_result else 0.0,
                'risk_level': fraud_result.risk_level if fraud_result else 'Unknown',
                'suspicious_patterns': fraud_result.suspicious_patterns if fraud_result else [],
                'confidence_score': fraud_result.confidence_score if fraud_result else 0.0,
                'blockchain_hash': fraud_result.blockchain_hash if fraud_result else None,
                'audit_trail_id': fraud_result.audit_trail_id if fraud_result else None
            } if enable_fraud_detection else None,
            'blockchain': blockchain_result if enable_blockchain else None,
            'processing_options': {
                'blockchain_enabled': enable_blockchain,
                'fraud_detection_enabled': enable_fraud_detection,
                'audit_trail_enabled': enable_audit_trail
            }
        }
        
        # Save comprehensive results
        results_file = os.path.join(app.config['RESULTS_FOLDER'], f"{unique_filename}_analysis.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Document processing error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/fees')
def get_service_fees():
    """Get current blockchain service fees"""
    try:
        fees = blockchain_manager.get_service_fees()
        return jsonify(fees)
    except Exception as e:
        logger.error(f"Error fetching service fees: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/verify/<document_hash>')
def verify_document(document_hash):
    """Verify document on blockchain"""
    try:
        verification_result = blockchain_manager.verify_document(document_hash)
        return jsonify(verification_result)
    except Exception as e:
        logger.error(f"Error verifying document: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history/<document_hash>')
def get_document_history(document_hash):
    """Get document processing history"""
    try:
        history = blockchain_manager.get_document_history(document_hash)
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error fetching document history: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/download/<filename>')
def download_file(filename):
    """Download processed files"""
    try:
        # Check both output folders
        for folder in [app.config['OUTPUT_FOLDER'], app.config['RESULTS_FOLDER']]:
            file_path = os.path.join(folder, filename)
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True)
        
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/preview/<filename>')
def preview_file(filename):
    """Preview uploaded file before processing"""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return render_template('preview.html', filename=filename)
    else:
        return "File not found", 404

@app.route('/result/<filename>')
def result_file(filename):
    """Show processing results"""
    # Load analysis results if available
    results_file = os.path.join(app.config['RESULTS_FOLDER'], f"{filename}_analysis.json")
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            results = json.load(f)
        return render_template('result.html', filename=filename, results=results)
    else:
        return "Results not found", 404

# ==================== API ROUTES ====================

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    """Handle Google authentication"""
    try:
        data = request.get_json()
        google_token = data.get('google_token')
        user_info = data.get('user_info', {})
        
        if not google_token:
            return jsonify({
                'success': False,
                'error': 'Missing Google token'
            }), 400
        
        # Store user info in session
        session['user_id'] = user_info.get('email', 'google_user')
        session['user_name'] = user_info.get('name', 'Google User')
        session['auth_type'] = 'google'
        
        return jsonify({
            'success': True,
            'message': 'Google authentication successful',
            'user': {
                'name': user_info.get('name'),
                'email': user_info.get('email'),
                'picture': user_info.get('picture')
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/auth/stacks', methods=['POST'])
def stacks_auth():
    """Handle Stacks/Leather wallet authentication"""
    try:
        data = request.get_json()
        user_session = data.get('userSession', {})
        auth_data = data.get('authData', {})
        
        if not user_session and not auth_data:
            return jsonify({
                'success': False,
                'error': 'Missing Stacks authentication data'
            }), 400
        
        # Extract user data from Stacks authentication
        user_data = user_session.get('userData') or auth_data.get('userSession', {}).get('userData', {})
        profile = user_data.get('profile', {})
        
        # Get the appropriate Stacks address (testnet or mainnet)
        stx_addresses = profile.get('stxAddress', {})
        wallet_address = stx_addresses.get('testnet') or stx_addresses.get('mainnet')
        
        if not wallet_address:
            return jsonify({
                'success': False,
                'error': 'No Stacks address found in authentication data'
            }), 400
        
        # Store authentication info in session
        session['user_id'] = wallet_address
        session['wallet_address'] = wallet_address
        session['wallet_type'] = 'leather'
        session['wallet_network'] = 'testnet' if stx_addresses.get('testnet') else 'mainnet'
        session['auth_type'] = 'stacks'
        session['user_name'] = profile.get('name', 'Stacks User')
        session['user_profile'] = profile
        
        logger.info(f"Stacks authentication successful: {wallet_address[:8]}...")
        
        return jsonify({
            'success': True,
            'message': 'Stacks authentication successful',
            'user': {
                'name': profile.get('name', 'Stacks User'),
                'stxAddress': wallet_address,
                'network': session['wallet_network'],
                'profile': profile
            },
            'wallet': {
                'type': 'leather',
                'address': wallet_address,
                'network': session['wallet_network']
            }
        })
        
    except Exception as e:
        logger.error(f"Stacks authentication error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/wallet/connect', methods=['POST'])
def connect_wallet():
    """Handle wallet connection requests with enhanced Leather wallet support"""
    try:
        data = request.get_json()
        wallet_type = data.get('wallet_type')
        wallet_address = data.get('wallet_address')
        network = data.get('network', 'testnet')
        user_data = data.get('user_data', {})
        
        if not wallet_type or not wallet_address:
            return jsonify({
                'success': False,
                'error': 'Missing wallet type or address'
            }), 400
        
        # Validate wallet address format based on wallet type
        if wallet_type == 'leather':
            # Stacks addresses start with 'ST' (testnet) or 'SP' (mainnet)
            if not (wallet_address.startswith('ST') or wallet_address.startswith('SP')):
                return jsonify({
                    'success': False,
                    'error': 'Invalid Stacks address format'
                }), 400
                
        elif wallet_type == 'metamask':
            # Ethereum addresses start with '0x' and are 42 characters long
            if not (wallet_address.startswith('0x') and len(wallet_address) == 42):
                return jsonify({
                    'success': False,
                    'error': 'Invalid Ethereum address format'
                }), 400
        
        # Store wallet info in session
        session['wallet_type'] = wallet_type
        session['wallet_address'] = wallet_address
        session['wallet_network'] = network if wallet_type == 'leather' else 'ethereum'
        session['user_id'] = wallet_address  # Use wallet address as user ID
        session['auth_type'] = 'wallet'
        
        # Store additional user data if provided (from Stacks Connect)
        if user_data:
            session['user_name'] = user_data.get('name', 'Wallet User')
            session['user_profile'] = user_data
        
        logger.info(f"Wallet connected: {wallet_type} - {wallet_address[:8]}...")
        
        return jsonify({
            'success': True,
            'message': f'{wallet_type.title()} wallet connected successfully',
            'wallet_address': wallet_address,
            'network': session['wallet_network'],
            'wallet_type': wallet_type,
            'session_id': session.get('user_id')
        })
        
    except Exception as e:
        logger.error(f"Wallet connection error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/blockchain/register', methods=['POST'])
def register_on_blockchain():
    """Register document on blockchain"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        metadata = request.form.to_dict()
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_blockchain_{filename}")
        file.save(temp_path)
        
        # Read file content for hashing
        with open(temp_path, 'rb') as f:
            file_content = f.read()
        
        # Prepare metadata with timestamp
        blockchain_metadata = {
            **metadata,
            'filename': filename,
            'file_size': len(file_content),
            'registration_time': datetime.now().isoformat(),
            'network': 'testnet',
            'user_id': session.get('user_id', 'anonymous')
        }
        
        # Generate document hash
        document_hash = blockchain_manager.generate_document_hash(file_content, blockchain_metadata)
        
        # Register on blockchain
        registration_result = blockchain_manager.register_document(
            document_hash,
            blockchain_metadata,
            session.get('wallet_address')
        )
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return jsonify(registration_result)
        
    except Exception as e:
        logger.error(f"Blockchain registration error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/analyze-fraud', methods=['POST'])
def analyze_fraud():
    """Analyze document for fraud using enhanced fraud detector"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_fraud_{filename}")
        file.save(temp_path)
        
        # Prepare metadata
        metadata = {
            'filename': filename,
            'upload_time': datetime.now().isoformat(),
            'file_size': os.path.getsize(temp_path),
            'analysis_type': 'fraud_detection',
            'user_id': session.get('user_id', 'anonymous')
        }
        
        # Analyze for fraud
        fraud_result = fraud_detector.analyze_document(temp_path, metadata)
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        # Return results
        return jsonify({
            'success': True,
            'fraud_analysis': {
                'fraud_probability': fraud_result.fraud_probability,
                'risk_level': fraud_result.risk_level,
                'confidence_score': fraud_result.confidence_score,
                'suspicious_patterns': fraud_result.suspicious_patterns,
                'blockchain_hash': fraud_result.blockchain_hash,
                'audit_trail_id': fraud_result.audit_trail_id,
                'recommendations': fraud_result.analysis_details.get('recommendations', [])
            }
        })
        
    except Exception as e:
        logger.error(f"Fraud analysis error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'fraud_detector': True,
            'blockchain_manager': True,
            'firebase': FIREBASE_AVAILABLE,
            'upload_folder': os.path.exists(UPLOAD_FOLDER),
            'output_folder': os.path.exists(OUTPUT_FOLDER)
        }
    })

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("🚀 Starting SecuredDoc Application...")
    print("📁 Upload folder:", UPLOAD_FOLDER)
    print("📁 Output folder:", OUTPUT_FOLDER)
    print("🌐 Server will be available at: http://localhost:5001")
    print("🔗 Routes available:")
    print("   • / (Home)")
    print("   • /dashboard (Main Dashboard)")
    print("   • /login (Authentication)")
    print("   • /auth (Enhanced Features)")
    print("   • /process (Document Processing)")
    
    app.run(host='0.0.0.0', port=5001, debug=True)
