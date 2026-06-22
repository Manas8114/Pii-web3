"""
IPFS Uploader — Decentralized Document Storage via Pinata
Uploads processed/redacted documents to IPFS and returns the CID + gateway URL.
"""

import os
import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)

PINATA_API_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS"
PINATA_GATEWAY = "https://gateway.pinata.cloud/ipfs"


def _get_api_key():
    """Get Pinata API key from environment."""
    return os.getenv('PINATA_API_KEY', '')


def _get_api_secret():
    """Get Pinata API secret from environment."""
    return os.getenv('PINATA_API_SECRET', '')


def upload_to_ipfs(file_path, metadata=None):
    """
    Upload a file to IPFS via Pinata.
    
    Args:
        file_path: Absolute path to the file to upload
        metadata: Optional dict with extra metadata to attach
    
    Returns:
        dict with ipfs_hash (CID), gateway_url, pin_size, timestamp, and success status
    """
    if not os.path.exists(file_path):
        return _error_result("File not found")

    api_key = _get_api_key()
    api_secret = _get_api_secret()

    if not api_key or not api_secret:
        logger.warning("PINATA_API_KEY/SECRET not set — using demo IPFS mode")
        return _demo_upload(file_path, metadata)

    try:
        headers = {
            'pinata_api_key': api_key,
            'pinata_secret_api_key': api_secret
        }

        filename = os.path.basename(file_path)

        keyvalues: dict = {
            "app": "SecuredDoc",
            "type": "redacted_document"
        }
        if metadata:
            keyvalues.update({
                k: str(v) for k, v in metadata.items()
            })
        pinata_metadata = {
            "name": filename,
            "keyvalues": keyvalues
        }

        import json
        pinata_options = {"cidVersion": 1}

        with open(file_path, 'rb') as f:
            files = {
                'file': (filename, f),
                'pinataMetadata': (None, json.dumps(pinata_metadata)),
                'pinataOptions': (None, json.dumps(pinata_options))
            }
            
            response = requests.post(
                PINATA_API_URL,
                headers=headers,
                files=files,
                timeout=60
            )

        if response.status_code == 200:
            data = response.json()
            ipfs_hash = data.get('IpfsHash', '')
            return {
                "success": True,
                "ipfs_hash": ipfs_hash,
                "gateway_url": f"{PINATA_GATEWAY}/{ipfs_hash}",
                "pin_size": data.get('PinSize', 0),
                "timestamp": data.get('Timestamp', ''),
                "storage": "ipfs_pinata"
            }
        else:
            logger.error(f"Pinata API error {response.status_code}: {response.text}")
            return _demo_upload(file_path, metadata)

    except Exception as e:
        logger.error(f"IPFS upload error: {e}")
        return _demo_upload(file_path, metadata)


def _demo_upload(file_path: str, metadata: Optional[dict] = None) -> dict:  # type: ignore[type-arg]
    """
    Return an honest 'not configured' result when Pinata API keys are absent.
    Does NOT claim success — the file is NOT stored anywhere.
    """
    return {
        "success": False,
        "ipfs_hash": None,
        "gateway_url": None,
        "pin_size": 0,
        "timestamp": "",
        "storage": "demo_simulated",
        "error": "Pinata API keys not configured — no actual upload performed",
        "note": "Set PINATA_API_KEY and PINATA_API_SECRET in .env for real IPFS uploads"
    }


def _error_result(message):
    """Return a standardized error result."""
    return {
        "success": False,
        "ipfs_hash": None,
        "gateway_url": None,
        "pin_size": 0,
        "timestamp": "",
        "storage": "error",
        "error": message
    }
