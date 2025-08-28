import fitz  # PyMuPDF
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

# Set up Presidio Analyzer and Anonymizer
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Define color for redaction mask (BLACK)
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

def get_sensitive_data(text):
    """Detect sensitive information using Presidio."""
    analysis_results = analyzer.analyze(text=text, entities=None, language="en")
    sensitive_data = {result.text: result.entity_type for result in analysis_results}
    return sensitive_data

def redact_text_with_pymupdf(doc):
    """Redact sensitive text by covering it with a black box in the PDF."""
    for page in doc:
        page.wrap_contents()  # Ensures correct text positioning
        text = page.get_text("text")
        
        # Detect sensitive info
        sensitive_data = get_sensitive_data(text)
        
        for data in sensitive_data.keys():
            raw_areas = page.search_for(data)
            for area in raw_areas:
                extracted_text = page.get_text("text", clip=area).strip()
                if extracted_text == data:
                    page.add_redact_annot(area, fill=color_map[COLOR_MASK])

        page.apply_redactions()
    
    return doc

def tokenize_text(text):
    """Tokenize text using spaCy."""
    nlp = spacy.load("en_core_web_lg")
    doc = nlp(text)
    tokens = [token.text for token in doc]
    return tokens

def process_pdf(pdf_path, output_pdf):
    """Complete process: Extract text, redact sensitive info, tokenize, and save."""
    text, doc = extract_text_from_pdf(pdf_path)

    # Redact sensitive data in PDF
    redacted_doc = redact_text_with_pymupdf(doc)

    # Save the redacted PDF
    redacted_doc.save(output_pdf)
    print(f"✅ Redacted PDF saved as: {output_pdf}")

    # Tokenize redacted text
    redacted_text = extract_text_from_pdf(output_pdf)[0]
    tokens = tokenize_text(redacted_text)
    print("\n🔹 Tokenized Text:\n", tokens)

    return tokens

if __name__ == "__main__":
    input_pdf = "D:\CodeFest(tokenization)\Codefest_Token\Codefest_Token\Harsh_Resume_current_picture__.pdf"  # Change to your input file
    output_pdf = "redacted_output.pdf"

    # Run the full process
    tokens = process_pdf(input_pdf, output_pdf)
