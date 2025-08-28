from flask import Flask, request, send_file, render_template
import pytesseract
from PIL import Image
from transformers import pipeline
import os
from werkzeug.utils import secure_filename
import fitz  # PyMuPDF
import spacy
import cv2
import numpy as np
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from transformers import pipeline
from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts
from typing import List

app = Flask(__name__)
# Define the upload and output directories
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

# Ensure the folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ✅ Load spaCy model
try:
    nlp = spacy.load("en_core_web_lg")
except OSError:
    print("Downloading en_core_web_lg model...")
    os.system("spacy download en_core_web_lg")
    nlp = spacy.load("en_core_web_lg")

# ✅ Load Transformers NER model
transformers_model = pipeline(
    "token-classification",
    model="dbmdz/bert-large-cased-finetuned-conll03-english",
    aggregation_strategy="average",
    ignore_labels=["O", "MISC"]
)

# ✅ Custom Entity Recognizer
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

# ✅ Initialize Presidio
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# ✅ Register the Transformers-based recognizer
transformers_recognizer = TransformersRecognizer(transformers_model)
analyzer.registry.add_recognizer(transformers_recognizer)

# ✅ Color Mapping for Redaction
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

def get_sensitive_data(text):
    analysis_results = analyzer.analyze(text=text, entities=None, language="en")

    sensitive_data = {}

    for result in analysis_results:
        entity_text = text[result.start:result.end]  # Extract actual sensitive text
        entity_label = result.entity_type  # Get entity label
        confidence_score = result.score  # Confidence score

        # Store entity in dictionary
        sensitive_data[entity_text] = entity_label

    return sensitive_data

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

    return output_image_path


def process_pdf(pdf_path, output_pdf, blur=False):
    """Complete process: Extract text, detect sensitive info, tokenize, redact/blur, and save."""
    text, doc = extract_text_from_pdf(pdf_path)

    # ✅ Redact or blur sensitive data in PDF
    redacted_doc = redact_text_with_pymupdf(doc, blur=blur)

    # ✅ Save the redacted/blurred PDF
    redacted_doc.save(output_pdf)

    return output_pdf

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_file', methods=['POST'])
def process_file_endpoint():
    """API endpoint for processing PDFs and images."""
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    
    if file.filename == '':
        return "No selected file", 400
    
    # Secure the filename and save
    filename = secure_filename(file.filename)
    input_path = os.path.join('uploads', filename)
    file.save(input_path)

    output_path = os.path.join('outputs', 'processed_' + filename)
    
    # Check file type (PDF or Image)
    if filename.lower().endswith('.pdf'):
        # Process PDF
        processed_pdf = process_pdf(input_path, output_path, blur=False)
        return send_file(processed_pdf, as_attachment=True)
    
    elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        # Process Image
        processed_image = process_image(input_path, output_path, blur=False)
        return send_file(processed_image, as_attachment=True)
    
    else:
        return "Unsupported file format", 400

if __name__ == '__main__':
    app.run(debug=True)
