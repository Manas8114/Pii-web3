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


# Example data to test storing in Firestore
sensitive_data = {
    "12345": {
        "safe_token": "892a94b0-c599-49e4-a1cd-138387b5fd94",
        "entity": "IN_PAN",  # Example entity type
        "confidence_score": 0.95
    },
    "67890": {
        "safe_token": "a32b56ff-1c47-426b-bc78-dc50146f8fd6",
        "entity": "IN_AADHAR",  # Another entity type
        "confidence_score": 0.88
    }
}

# Call the function to store the data
store_sensitive_data_firestore(sensitive_data)
