import os
import pandas as pd
import numpy as np
import re
import spacy
from google.cloud import firestore
import google.auth
import google.generativeai as genai

# Initialize Firestore client (optional)
db = firestore.Client()

try:
    nlp = spacy.load("en_core_web_lg")
except OSError:
    print("Downloading en_core_web_lg model...")
    os.system("spacy download en_core_web_lg")
    nlp = spacy.load("en_core_web_lg")

# Define regex patterns for PII detection
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}",
    "date": r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2}|\b(?:[A-Za-z]+[\s]*\d{1,2},?\s*\d{4})\b)\b",
     "year":r"^(19[0-9]{2}|20[0-4][0-9]|2050)$"
}

# Tokenization logic
def generate_safe_token(value, token_index, label):
    """Generate a hashed token for PII with a label"""
    return f"{label}_TOKEN_{token_index}"

def detect_and_tokenize_pii(df):
    """Detect PII in the dataframe and replace with tokens"""
    pii_mapping = {}  # Store original PII → Token mapping
    sensitive_data = {}  # Store sensitive data and its origin
    tokenized_data = {}  # Store tokenized PII data for reference
    token_index = 1  # Track token indices for unique token generation

    # 1. Use regex patterns to detect emails, phone numbers, etc.
    for col in df.columns:
        for pii_type, pattern in PII_PATTERNS.items():
            df[col] = df[col].astype(str)  # Ensure column is string type
            matches = df[col].str.findall(pattern)

            for i, match_list in enumerate(matches):
                for match in match_list:
                    if match not in pii_mapping:
                        token = generate_safe_token(match, token_index, pii_type)
                        pii_mapping[match] = token
                        token_index += 1
                    
                    df.at[i, col] = df.at[i, col].replace(match, pii_mapping[match])

    # 2. Use spaCy NER to detect names, organizations, and locations.
    for col in df.columns:
        for i, value in enumerate(df[col]):
            doc = nlp(str(value))  # Process the text with spaCy
            for ent in doc.ents:
                if ent.label_ in ["PERSON", "ORG", "GPE"]:  # Detect PII entities
                    if ent.text not in pii_mapping:
                        token = generate_safe_token(ent.text, token_index, ent.label_)
                        pii_mapping[ent.text] = token
                        token_index += 1
                    
                    df.at[i, col] = df.at[i, col].replace(ent.text, pii_mapping[ent.text])

    return df, pii_mapping, sensitive_data, tokenized_data

import os
import pandas as pd

def process_csv_file(filename):
    """Process and anonymize .csv files."""
    df = pd.read_csv(filename)
    df = df.astype(str).replace('nan', np.nan)

    # Assuming detect_and_tokenize_pii returns 4 values
    anonymized_df, pii_mapping, sensitive_data, tokenized_data = detect_and_tokenize_pii(df)

    # Create output directory if it doesn't exist
    output_dir = "anon_output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Correctly join the directory path with the file name
    output_file = os.path.join(output_dir, f"anon_{os.path.basename(filename)}")
    
    # Save the anonymized CSV to the directory
    anonymized_df.to_csv(output_file, index=False)

    print(f"✅ Anonymized CSV saved: {output_file}")


def main():
    """Process CSV file"""
    # Ask the user to input the filename
    file_input = r"D:\CodeFest(tokenization)\Codefest_Token\Models\pii_mixed_data.csv"
    
    process_csv_file(file_input)

if __name__ == "__main__":
    main()
