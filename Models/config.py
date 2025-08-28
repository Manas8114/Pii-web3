import firebase_admin
from firebase_admin import credentials, firestore
import os

# 🔹 Load Firebase credentials
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIREBASE_CREDENTIALS = os.path.join(BASE_DIR, "serviceAccountKey.json")

# 🔹 Initialize Firestore (no database URL required)
cred = credentials.Certificate(FIREBASE_CREDENTIALS)
firebase_admin.initialize_app(cred)

db = firestore.client()  # Firestore database instance

# 🔹 Example: Add data to Firestore
def store_sensitive_data_firestore(sensitive_data):
    for entity_text, details in sensitive_data.items():
        safe_token = details["safe_token"]

        # Store data in Firestore collection
        db.collection("tokens").document(safe_token).set({
            "original_text": entity_text,
            "entity": details["entity"],
            "confidence_score": details["confidence_score"]
        })

    print("✅ Data stored in Firestore!")

