import os
import io
import json
import uuid
import fitz  # PyMuPDF
import cv2
import numpy as np
import datetime
from PIL import Image
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class DocumentFraudDetector:
    def __init__(self):
        self.results = {
            'forensics': {},
            'content_validation': {},
            'security_features': {},
            'overall_risk': 'Unknown'
        }
    
    def check_metadata(self, pdf_path):
        """Check document metadata for inconsistencies and tampering"""
        try:
            doc = fitz.open(pdf_path)
            metadata = doc.metadata
            
            # Extract creation and modification dates
            creation_date = metadata.get('creationDate', '')
            mod_date = metadata.get('modDate', '')
            
            # Process PDF date format: D:YYYYMMDDHHmmSS
            def parse_pdf_date(date_str):
                if not date_str or not date_str.startswith('D:'):
                    return None
                try:
                    # Extract basic date components
                    date_str = date_str[2:]  # Remove 'D:'
                    year = int(date_str[0:4])
                    month = int(date_str[4:6])
                    day = int(date_str[6:8])
                    hour = int(date_str[8:10]) if len(date_str) > 8 else 0
                    minute = int(date_str[10:12]) if len(date_str) > 10 else 0
                    second = int(date_str[12:14]) if len(date_str) > 12 else 0
                    return datetime.datetime(year, month, day, hour, minute, second)
                except (ValueError, IndexError):
                    return None
            
            creation_datetime = parse_pdf_date(creation_date)
            mod_datetime = parse_pdf_date(mod_date)
            
            # Check if modification date is before creation date
            if creation_datetime and mod_datetime and mod_datetime < creation_datetime:
                self.results['forensics']['metadata_time_inconsistency'] = True
            else:
                self.results['forensics']['metadata_time_inconsistency'] = False
            
            # Check creator and producer fields
            creator = metadata.get('creator', '')
            producer = metadata.get('producer', '')
            
            # Check for empty metadata (might indicate scrubbing)
            metadata_empty = not any([creation_date, mod_date, creator, producer])
            self.results['forensics']['metadata_empty'] = metadata_empty
            
            # Check for common fraudulent manipulation tools
            suspicious_tools = ['Acrobat Distiller', 'PDF Editor', 'ABBYY FineReader']
            tool_matches = [tool for tool in suspicious_tools if tool.lower() in producer.lower()]
            self.results['forensics']['suspicious_creation_tools'] = len(tool_matches) > 0
            
            doc.close()
            return True
            
        except Exception as e:
            print(f"Metadata check error: {e}")
            self.results['forensics']['metadata_error'] = str(e)
            return False
    
    def detect_image_manipulation(self, pdf_path):
        """Analyze document images for signs of manipulation"""
        try:
            doc = fitz.open(pdf_path)
            manipulation_detected = False
            
            # For each page in the PDF
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                
                # Extract images
                img_list = page.get_images(full=True)
                
                # If there are images on this page
                for img_index, img in enumerate(img_list):
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    
                    # Convert to numpy array for OpenCV processing
                    nparr = np.frombuffer(image_bytes, np.uint8)
                    img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    
                    if img_np is not None:
                        # 1. Error Level Analysis simulation (simplified)
                        gray = cv2.cvtColor(img_np, cv2.COLOR_BGR2GRAY)
                        ela_result = self._check_ela(img_np)
                        
                        # 2. Check for clone detection (simplified)
                        clone_result = self._check_cloning(gray)
                        
                        # 3. Check compression inconsistencies
                        compression_result = self._check_compression(img_np)
                        
                        if ela_result or clone_result or compression_result:
                            manipulation_detected = True
                            break
                
                if manipulation_detected:
                    break
            
            self.results['forensics']['image_manipulation_detected'] = manipulation_detected
            doc.close()
            return True
            
        except Exception as e:
            print(f"Image manipulation check error: {e}")
            self.results['forensics']['image_analysis_error'] = str(e)
            return False
    
    def _check_ela(self, img, quality=90):
        """Error Level Analysis (simplified)"""
        try:
            # Convert to PIL Image
            img_pil = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
            
            # Save with specific quality
            buffer = io.BytesIO()
            img_pil.save(buffer, format='JPEG', quality=quality)
            buffer.seek(0)
            
            # Load compressed image
            compressed_img = Image.open(buffer)
            compressed_np = np.array(compressed_img)
            
            # Convert back to OpenCV format
            orig_np = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            compressed_np = cv2.cvtColor(compressed_np, cv2.COLOR_RGB2BGR)
            
            # Calculate difference
            diff = cv2.absdiff(orig_np, compressed_np)
            
            # Check if significant differences exist
            mean_diff = np.mean(diff)
            std_diff = np.std(diff)
            
            # Look for unusually high ELA values (potential manipulation)
            suspicious = std_diff > 15.0  # Threshold can be tuned based on testing
            
            return suspicious
            
        except Exception as e:
            print(f"ELA check error: {e}")
            return False
    
    def _check_cloning(self, gray_img):
        """Check for cloned areas using simplified detection"""
        try:
            # Apply SIFT or ORB to detect keypoints (using ORB as it's faster)
            orb = cv2.ORB_create()
            keypoints, descriptors = orb.detectAndCompute(gray_img, None)
            
            # If no keypoints found, return
            if descriptors is None or len(descriptors) < 10:
                return False
                
            # Create BFMatcher
            bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
            
            # Match descriptors with themselves
            matches = bf.match(descriptors, descriptors)
            
            # Filter out self-matches
            filtered_matches = []
            for m in matches:
                # Skip identity matches (same keypoint)
                if m.queryIdx != m.trainIdx:
                    filtered_matches.append(m)
            
            # If too many matches between different regions, it might indicate cloning
            # This is a simplified heuristic
            clone_threshold = len(keypoints) * 0.15  # Adjust based on testing
            
            return len(filtered_matches) > clone_threshold
            
        except Exception as e:
            print(f"Clone detection error: {e}")
            return False
    
    def _check_compression(self, img):
        """Check for inconsistent compression artifacts"""
        try:
            # Convert to YCrCb color space to separate luminance from chrominance
            ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
            y, cr, cb = cv2.split(ycrcb)
            
            # Apply DCT (Discrete Cosine Transform)
            h, w = y.shape
            
            # Create blocks of 8x8 (standard JPEG compression block size)
            blocks_h = h // 8
            blocks_w = w // 8
            
            # Check consistency of DCT coefficients across blocks
            inconsistent_blocks = 0
            total_blocks = 0
            
            for i in range(blocks_h):
                for j in range(blocks_w):
                    block = y[i*8:(i+1)*8, j*8:(j+1)*8].astype(np.float32)
                    dct = cv2.dct(block)
                    
                    # Check for abrupt changes in high-frequency coefficients
                    high_freq = dct[4:, 4:]
                    mean_high = np.mean(np.abs(high_freq))
                    
                    # Adjacent blocks should have similar high-frequency characteristics
                    # Large differences might indicate manipulation
                    if i > 0 and j > 0:
                        prev_block_h = y[(i-1)*8:i*8, j*8:(j+1)*8].astype(np.float32)
                        prev_dct_h = cv2.dct(prev_block_h)
                        prev_high_h = np.mean(np.abs(prev_dct_h[4:, 4:]))
                        
                        prev_block_w = y[i*8:(i+1)*8, (j-1)*8:j*8].astype(np.float32)
                        prev_dct_w = cv2.dct(prev_block_w)
                        prev_high_w = np.mean(np.abs(prev_dct_w[4:, 4:]))
                        
                        # Check if current block differs significantly from both adjacent blocks
                        if (abs(mean_high - prev_high_h) > 15 and abs(mean_high - prev_high_w) > 15):
                            inconsistent_blocks += 1
                    
                    total_blocks += 1
            
            # Calculate ratio of inconsistent blocks
            if total_blocks > 0:
                inconsistency_ratio = inconsistent_blocks / total_blocks
                return inconsistency_ratio > 0.08  # Threshold can be adjusted
            
            return False
            
        except Exception as e:
            print(f"Compression check error: {e}")
            return False
    
    def check_content_consistency(self, pdf_path):
        """Check document content for logical inconsistencies"""
        try:
            doc = fitz.open(pdf_path)
            text_content = ""
            
            # Extract text from all pages
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                text_content += page.get_text()
            
            # Check for logical inconsistencies in text (simplified)
            inconsistencies = []
            
            # 1. Check for date inconsistencies
            date_inconsistency = self._check_date_inconsistencies(text_content)
            if date_inconsistency:
                inconsistencies.append("Date inconsistency detected")
            
            # 2. Check for numeric inconsistencies
            numeric_inconsistency = self._check_numeric_inconsistencies(text_content)
            if numeric_inconsistency:
                inconsistencies.append("Numeric value inconsistency detected")
            
            # 3. Check for internal reference inconsistencies
            ref_inconsistency = self._check_reference_inconsistencies(text_content)
            if ref_inconsistency:
                inconsistencies.append("Internal reference inconsistency detected")
            
            self.results['content_validation']['logical_inconsistencies'] = inconsistencies
            self.results['content_validation']['inconsistencies_found'] = len(inconsistencies) > 0
            
            doc.close()
            return True
            
        except Exception as e:
            print(f"Content consistency check error: {e}")
            self.results['content_validation']['content_check_error'] = str(e)
            return False
    
    def _check_date_inconsistencies(self, text):
        """Check for inconsistent dates within the document"""
        import re
        from datetime import datetime
        
        # Look for dates in common formats
        # Format: MM/DD/YYYY or DD/MM/YYYY or YYYY-MM-DD
        date_patterns = [
            r'(\d{1,2})/(\d{1,2})/(\d{4})',  # MM/DD/YYYY or DD/MM/YYYY
            r'(\d{4})-(\d{1,2})-(\d{1,2})'   # YYYY-MM-DD
        ]
        
        dates = []
        
        # Extract all dates
        for pattern in date_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                date_str = match.group(0)
                try:
                    # Try different date formats
                    if '/' in date_str:
                        parts = date_str.split('/')
                        if len(parts) == 3:
                            # Try both MM/DD/YYYY and DD/MM/YYYY
                            try:
                                date = datetime.strptime(date_str, '%m/%d/%Y')
                            except ValueError:
                                try:
                                    date = datetime.strptime(date_str, '%d/%m/%Y')
                                except ValueError:
                                    continue
                            dates.append(date)
                    elif '-' in date_str:
                        date = datetime.strptime(date_str, '%Y-%m-%d')
                        dates.append(date)
                except ValueError:
                    continue
        
        # Look for chronological inconsistencies
        # e.g., a document dated 2023 referencing events in 2024
        if dates:
            min_date = min(dates)
            max_date = max(dates)
            
            # Check for suspicious date ranges
            future_references = max_date.year > datetime.now().year
            
            # Check if document has dates spanning more than 5 years (suspicious for some document types)
            year_span_suspicious = (max_date.year - min_date.year) > 5
            
            return future_references or year_span_suspicious
        
        return False
    
    def _check_numeric_inconsistencies(self, text):
        """Check for inconsistent numeric values within the document"""
        import re
        
        # Look for currency amounts
        # Format: $X,XXX.XX or X,XXX.XX USD or EUR X.XXX,XX
        currency_patterns = [
            r'\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)',  # $X,XXX.XX
            r'(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\s*(?:USD|EUR|GBP)',  # X,XXX.XX USD
            r'(?:EUR|GBP)\s*(\d{1,3}(?:.\d{3})*(?:,\d{2})?)'  # EUR X.XXX,XX
        ]
        
        amounts = []
        
        # Extract all currency amounts
        for pattern in currency_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                try:
                    # Extract the numeric part
                    if '$' in match.group(0):
                        # Format: $X,XXX.XX
                        amount_str = match.group(1)
                        # Remove commas and convert to float
                        amount = float(amount_str.replace(',', ''))
                    elif 'USD' in match.group(0) or 'EUR' in match.group(0) or 'GBP' in match.group(0):
                        if re.search(r'EUR\s*\d', match.group(0)) or re.search(r'GBP\s*\d', match.group(0)):
                            # Format: EUR X.XXX,XX
                            amount_str = match.group(1)
                            # Replace dots in thousands and comma for decimal point
                            amount = float(amount_str.replace('.', '').replace(',', '.'))
                        else:
                            # Format: X,XXX.XX USD
                            amount_str = match.group(1)
                            # Remove commas and convert to float
                            amount = float(amount_str.replace(',', ''))
                    
                    amounts.append(amount)
                except (ValueError, IndexError):
                    continue
        
        # Check for suspicious total/subtotal inconsistencies
        # This is a simplified check - in reality you'd need to look for subtotals and totals
        if len(amounts) >= 3:
            # Sort amounts
            sorted_amounts = sorted(amounts)
            
            # Check if the largest amount is suspiciously different from the sum of others
            total = sum(sorted_amounts[:-1])  # Sum all except the largest
            largest = sorted_amounts[-1]
            
            # If the largest amount is different from the sum by more than 1%
            if abs(total - largest) / largest > 0.01 and abs(total - largest) > 1.0:
                return True
        
        return False
    
    def _check_reference_inconsistencies(self, text):
        """Check for inconsistent internal references within the document"""
        import re
        
        # Look for references to sections, figures, or page numbers
        section_refs = re.findall(r'Section\s+(\d+(?:\.\d+)*)', text, re.IGNORECASE)
        figure_refs = re.findall(r'Figure\s+(\d+(?:\.\d+)*)', text, re.IGNORECASE)
        page_refs = re.findall(r'page\s+(\d+)', text, re.IGNORECASE)
        
        # Check if there are references to non-existent sections/figures
        # This is simplified - a real implementation would need to verify against actual document structure
        
        # Check for references to sections/figures beyond a reasonable range
        if section_refs:
            section_numbers = [int(s.split('.')[0]) for s in section_refs if '.' in s]
            if section_numbers and max(section_numbers) > 50:  # Arbitrary threshold
                return True
        
        if figure_refs:
            figure_numbers = [int(f.split('.')[0]) for f in figure_refs if '.' in f]
            if figure_numbers and max(figure_numbers) > 100:  # Arbitrary threshold
                return True
        
        if page_refs:
            page_numbers = [int(p) for p in page_refs]
            if page_numbers and max(page_numbers) > 1000:  # Arbitrary threshold
                return True
        
        return False
    
    def check_security_features(self, pdf_path):
        """Check document for security features like digital signatures"""
        try:
            doc = fitz.open(pdf_path)
            
            # Check for encryption
            is_encrypted = doc.isEncrypted
            self.results['security_features']['is_encrypted'] = is_encrypted
            
            # Check for digital signatures
            has_signatures = False
            
            # PyMuPDF approach for signatures
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                widgets = page.widgets()
                for widget in widgets:
                    if widget.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:
                        has_signatures = True
                        break
                        
                if has_signatures:
                    break
            
            self.results['security_features']['has_digital_signature'] = has_signatures
            
            # Check for document restrictions
            if is_encrypted:
                # Try with empty password first
                try:
                    if doc.authenticate(""):
                        permissions = doc.permissions
                        self.results['security_features']['permissions'] = permissions
                        self.results['security_features']['weak_encryption'] = True
                    else:
                        self.results['security_features']['requires_password'] = True
                except:
                    self.results['security_features']['requires_password'] = True
            
            doc.close()
            return True
            
        except Exception as e:
            print(f"Security features check error: {e}")
            self.results['security_features']['security_check_error'] = str(e)
            return False
    
    def calculate_risk_score(self):
        """Calculate overall risk score based on all checks"""
        risk_factors = 0
        total_factors = 0
        
        # Forensics factors
        forensics_checks = {
            'metadata_time_inconsistency': 1,
            'metadata_empty': 1,
            'suspicious_creation_tools': 1,
            'image_manipulation_detected': 2  # Higher weight
        }
        
        for check, weight in forensics_checks.items():
            if check in self.results['forensics']:
                total_factors += weight
                if self.results['forensics'][check] is True:
                    risk_factors += weight
        
        # Content validation factors
        if 'inconsistencies_found' in self.results['content_validation']:
            total_factors += 2  # Higher weight
            if self.results['content_validation']['inconsistencies_found']:
                risk_factors += 2
        
        # Security features factors (inverse - lack of security is a risk)
        security_checks = {
            'is_encrypted': -1,  # Being encrypted reduces risk
            'has_digital_signature': -1,  # Having signature reduces risk
            'weak_encryption': 1,  # Weak encryption increases risk
            'requires_password': -1  # Requiring password reduces risk
        }
        
        for check, weight in security_checks.items():
            if check in self.results['security_features']:
                if weight < 0:  # Inverse factor
                    total_factors += abs(weight)
                    if not self.results['security_features'][check]:
                        risk_factors += abs(weight)
                else:
                    total_factors += weight
                    if self.results['security_features'][check]:
                        risk_factors += weight
        
        # Calculate percentage
        risk_percentage = (risk_factors / total_factors * 100) if total_factors > 0 else 0
        
        # Determine risk level
        if risk_percentage >= 70:
            risk_level = "High"
        elif risk_percentage >= 40:
            risk_level = "Medium"
        elif risk_percentage >= 10:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        self.results['risk_percentage'] = risk_percentage
        self.results['overall_risk'] = risk_level
        
        return risk_level
    
    def analyze_document(self, pdf_path):
        """Run all fraud detection checks on a document"""
        # Reset results
        self.results = {
            'forensics': {},
            'content_validation': {},
            'security_features': {},
            'overall_risk': 'Unknown'
        }
        
        # Run checks
        self.check_metadata(pdf_path)
        self.detect_image_manipulation(pdf_path)
        self.check_content_consistency(pdf_path)
        self.check_security_features(pdf_path)
        
        # Calculate overall risk
        self.calculate_risk_score()
        
        return self.results


# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = str(uuid.uuid4()) + '.pdf'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze document
        detector = DocumentFraudDetector()
        results = detector.analyze_document(filepath)
        
        # Save results
        results_filename = filename.replace('.pdf', '_results.json')
        results_filepath = os.path.join(app.config['UPLOAD_FOLDER'], results_filename)
        
        with open(results_filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        return jsonify({
            'success': True,
            'results': results,
            'results_id': filename.replace('.pdf', '')
        })
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/results/<results_id>')
def view_results(results_id):
    results_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{results_id}_results.json")
    
    if not os.path.exists(results_filepath):
        return redirect(url_for('index'))
    
    with open(results_filepath, 'r') as f:
        results = json.load(f)
    
    return render_template('results.html', results=results)

@app.route('/export/<results_id>')
def export_results(results_id):
    results_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{results_id}_results.json")
    
    if not os.path.exists(results_filepath):
        return jsonify({'error': 'Results not found'}), 404
    
    return send_file(results_filepath, as_attachment=True, download_name=f"fraud_detection_report_{results_id}.json")

if __name__ == '__main__':
    # Create templates directory and add basic templates
    os.makedirs('templates', exist_ok=True)
    
    # Create index.html template
    with open('templates/index.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Fraud Detection</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .upload-form {
            margin: 20px 0;
            text-align: center;
        }
        .upload-box {
            border: 2px dashed #ccc;
            border-radius: 5px;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .upload-box:hover {
            background-color: #f9f9f9;
        }
        .upload-box input {
            display: none;
        }
        .upload-label {
            display: block;
            font-size: 16px;
            color: #555;
            margin-bottom: 10px;
        }
        .btn {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        .btn:hover {
            background-color: #45a049;
        }
        #loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 2s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        #error {
            color: #f00;
            text-align: center;
            margin: 10px 0;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Document Fraud Detection</h1>
        <p>Upload a PDF document to analyze it for potential fraud indicators.</p>
        
        <div class="upload-form">
            <form id="upload-form">
                <div class="upload-box" id="drop-area">
                    <span class="upload-label">Drag & Drop a PDF here or click to browse</span>
                    <input type="file" id="file-input" accept=".pdf" />
                </div>
                <button type="submit" class="btn">Analyze Document</button>
            </form>
        </div>
        
        <div id="loading">
            <div class="spinner"></div>
            <p>Analyzing document... This may take a minute.</p>
        </div>
        
        <div id="error"></div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const dropArea = document.getElementById('drop-area');
            const fileInput = document.getElementById('file-input');
            const uploadForm = document.getElementById('upload-form');
            const loading = document.getElementById('loading');
            const errorDisplay = document.getElementById('error');
            
            // Handle drag and drop events
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropArea.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            ['dragenter', 'dragover'].forEach(eventName => {
                dropArea.addEventListener(eventName, highlight, false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                dropArea.addEventListener(eventName, unhighlight, false);
            });
            
            function highlight() {
                dropArea.style.borderColor = '#4CAF50';
                dropArea.style.backgroundColor = '#f0f9f0';
            }
            
            function unhighlight() {
                dropArea.style.borderColor = '#ccc';
                dropArea.style.backgroundColor = '';
            }
            
            dropArea.addEventListener('drop', handleDrop, false);
            
            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                fileInput.files = files;
            }
            
            dropArea.addEventListener('click', function() {
                fileInput.click();
            });
            
            uploadForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                if (!fileInput.files[0]) {
                    errorDisplay.textContent = 'Please select a file first';
                    errorDisplay.style.display = 'block';
                    return;
                }
                
                const file = fileInput.files[0];
                if (!file.name.toLowerCase().endsWith('.pdf')) {
                    errorDisplay.textContent = 'Please upload a PDF file';
                    errorDisplay.style.display = 'block';
                    return;
                }
                
                const formData = new FormData();
                formData.append('file', file);
                
                errorDisplay.style.display = 'none';
                loading.style.display = 'block';
                
                fetch('/upload', {
                    method: 'POST',
                    body: formData
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Server error');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        window.location.href = '/results/' + data.results_id;
                    } else {
                        throw new Error(data.error || 'Unknown error');
                    }
                })
                .catch(error => {
                    errorDisplay.textContent = 'Error: ' + error.message;
                    errorDisplay.style.display = 'block';
                    loading.style.display = 'none';
                });
            });
        });
    </script>
</body>
</html>
        ''')
    
    # Create results.html template
    with open('templates/results.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fraud Detection Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .section {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        .high {
            background-color: #ffebee;
            border-left: 5px solid #f44336;
        }
        .medium {
            background-color: #fff8e1;
            border-left: 5px solid #ffb74d;
        }
        .low {
            background-color: #e8f5e9;
            border-left: 5px solid #66bb6a;
        }
        .minimal {
            background-color: #e3f2fd;
            border-left: 5px solid #42a5f5;
        }
        .unknown {
            background-color: #f5f5f5;
            border-left: 5px solid #9e9e9e;
        }
        .detail-list {
            list-style-type: none;
            padding-left: 0;
        }
        .detail-list li {
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        .detail-list li:last-child {
            border-bottom: none;
        }
        .icon {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-right: 5px;
            text-align: center;
            border-radius: 50%;
        }
        .icon-danger {
            background-color: #f44336;
            color: white;
        }
        .icon-warning {
            background-color: #ff9800;
            color: white;
        }
        .icon-success {
            background-color: #4caf50;
            color: white;
        }
        .icon-info {
            background-color: #2196f3;
            color: white;
        }
        .btn {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            text-decoration: none;
            display: inline-block;
            margin-top: 10px;
        }
        .btn:hover {
            background-color: #45a049;
        }
        .btn-secondary {
            background-color: #2196F3;
        }
        .btn-secondary:hover {
            background-color: #0b7dda;
        }
        .buttons {
            margin-top: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Document Fraud Detection Results</h1>
        
        <div class="section {{ results.overall_risk.lower() }}">
            <h2>Overall Risk Assessment: {{ results.overall_risk }}</h2>
            <p>Risk Score: {{ "%.1f"|format(results.risk_percentage) }}%</p>
        </div>
        
        <div class="section">
            <h2>Forensic Analysis</h2>
            <ul class="detail-list">
                {% if results.forensics.metadata_time_inconsistency is defined %}
                <li>
                    {% if results.forensics.metadata_time_inconsistency %}
                    <span class="icon icon-danger">!</span> Metadata timestamp inconsistency detected
                    {% else %}
                    <span class="icon icon-success">✓</span> No metadata timestamp inconsistency
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.forensics.metadata_empty is defined %}
                <li>
                    {% if results.forensics.metadata_empty %}
                    <span class="icon icon-warning">!</span> Document metadata appears to be empty or scrubbed
                    {% else %}
                    <span class="icon icon-success">✓</span> Document contains expected metadata
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.forensics.suspicious_creation_tools is defined %}
                <li>
                    {% if results.forensics.suspicious_creation_tools %}
                    <span class="icon icon-danger">!</span> Document created with potentially suspicious tools
                    {% else %}
                    <span class="icon icon-success">✓</span> No suspicious creation tools detected
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.forensics.image_manipulation_detected is defined %}
                <li>
                    {% if results.forensics.image_manipulation_detected %}
                    <span class="icon icon-danger">!</span> Evidence of image manipulation detected
                    {% else %}
                    <span class="icon icon-success">✓</span> No evidence of image manipulation
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.forensics.metadata_error is defined %}
                <li>
                    <span class="icon icon-warning">!</span> Error during metadata analysis: {{ results.forensics.metadata_error }}
                </li>
                {% endif %}
                
                {% if results.forensics.image_analysis_error is defined %}
                <li>
                    <span class="icon icon-warning">!</span> Error during image analysis: {{ results.forensics.image_analysis_error }}
                </li>
                {% endif %}
            </ul>
        </div>
        
        <div class="section">
            <h2>Content Validation</h2>
            <ul class="detail-list">
                {% if results.content_validation.inconsistencies_found is defined %}
                <li>
                    {% if results.content_validation.inconsistencies_found %}
                    <span class="icon icon-danger">!</span> Logical inconsistencies found in document content
                    {% else %}
                    <span class="icon icon-success">✓</span> No logical inconsistencies detected
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.content_validation.logical_inconsistencies is defined and results.content_validation.logical_inconsistencies %}
                <li>
                    <strong>Detected inconsistencies:</strong>
                    <ul>
                        {% for inconsistency in results.content_validation.logical_inconsistencies %}
                        <li>{{ inconsistency }}</li>
                        {% endfor %}
                    </ul>
                </li>
                {% endif %}
                
                {% if results.content_validation.content_check_error is defined %}
                <li>
                    <span class="icon icon-warning">!</span> Error during content validation: {{ results.content_validation.content_check_error }}
                </li>
                {% endif %}
            </ul>
        </div>
        
        <div class="section">
            <h2>Security Features</h2>
            <ul class="detail-list">
                {% if results.security_features.is_encrypted is defined %}
                <li>
                    {% if results.security_features.is_encrypted %}
                    <span class="icon icon-success">✓</span> Document is encrypted
                    {% else %}
                    <span class="icon icon-warning">!</span> Document is not encrypted
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.security_features.has_digital_signature is defined %}
                <li>
                    {% if results.security_features.has_digital_signature %}
                    <span class="icon icon-success">✓</span> Document contains digital signature
                    {% else %}
                    <span class="icon icon-warning">!</span> No digital signature found
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.security_features.weak_encryption is defined %}
                <li>
                    {% if results.security_features.weak_encryption %}
                    <span class="icon icon-danger">!</span> Document uses weak encryption
                    {% else %}
                    <span class="icon icon-success">✓</span> Document uses strong encryption
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.security_features.requires_password is defined %}
                <li>
                    {% if results.security_features.requires_password %}
                    <span class="icon icon-success">✓</span> Document requires password to open
                    {% else %}
                    <span class="icon icon-info">i</span> Document does not require password
                    {% endif %}
                </li>
                {% endif %}
                
                {% if results.security_features.security_check_error is defined %}
                <li>
                    <span class="icon icon-warning">!</span> Error during security check: {{ results.security_features.security_check_error }}
                </li>
                {% endif %}
            </ul>
        </div>
        
        <div class="buttons">
            <a href="/" class="btn btn-secondary">Analyze Another Document</a>
            <a href="/export/{{ request.path.split('/')[-1] }}" class="btn">Export Results</a>
        </div>
    </div>
</body>
</html>
        ''')
    
    app.run(debug=True)