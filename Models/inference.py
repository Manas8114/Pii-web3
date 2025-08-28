from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from transformers import pipeline
from typing import List
from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts
import os
import spacy
# Ensure spaCy model is available (only needed once)
try:
    nlp = spacy.load("en_core_web_lg")
except OSError:
    print("Downloading en_core_web_lg model...")
    os.system("spacy download en_core_web_lg")
    nlp = spacy.load("en_core_web_lg")

# Load the Transformers model once
transformers_model = pipeline(
    "token-classification",
    model="dbmdz/bert-large-cased-finetuned-conll03-english",
    aggregation_strategy="average",
    ignore_labels=["O", "MISC"]
)

class TransformersRecognizer(EntityRecognizer):
    def __init__(self, model_pipeline, supported_language="en"):
        self.pipeline = model_pipeline  # Reuse loaded pipeline
        self.label2presidio = {
            "PER": "PERSON",
            "LOC": "LOCATION",
            "ORG": "ORGANIZATION",
            "MISC": "MISC",  # Generic category
        }
        super().__init__(supported_entities=list(self.label2presidio.values()), supported_language=supported_language)

    def load(self) -> None:
        pass  # No need to load anything manually

    def analyze(self, text: str, entities: List[str] = None, nlp_artifacts: NlpArtifacts = None) -> List[RecognizerResult]:
        results = []
        predicted_entities = self.pipeline(text)

        for e in predicted_entities:
            converted_entity = self.label2presidio.get(e["entity_group"], None)
            if converted_entity and (entities is None or converted_entity in entities):
                results.append(RecognizerResult(entity_type=converted_entity, start=e["start"], end=e["end"], score=e["score"]))

        return results

# Initialize Presidio engines once
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Register the Transformers-based recognizer with preloaded model
transformers_recognizer = TransformersRecognizer(transformers_model)
analyzer.registry.add_recognizer(transformers_recognizer)

def process_text(text: str):
    """
    Analyze and anonymize text with all available entity types.
    """
    analysis_results = analyzer.analyze(
        text=text, 
        entities=None,  # Detect ALL entities available in Presidio
        language="en"
    )

    # Print detected entities
    print("\nDetected Entities:")
    for res in analysis_results:
        print(res)

    # Anonymize text
    anonymized_result = anonymizer.anonymize(text=text, analyzer_results=analysis_results)
    print("\nAnonymized Text:", anonymized_result.text)
    return anonymized_result.text  # Return anonymized text for further use

# ✅ Usage: Call process_text() multiple times without reloading the model
if __name__ == "__main__":
    sample_texts = [
        "Elon Musk works at SpaceX and lives in Texas. His email is elonmusk@tesla.com. His phone number is +1 123-456-7890. His credit card is 4111-1111-1111-1111.",
        "Jeff Bezos founded Amazon and lives in Washington. He was born on January 12, 1964.",
        "Sundar Pichai is the CEO of Google. His social security number is 123-45-6789."
    ]

    for txt in sample_texts:
        process_text(txt)
