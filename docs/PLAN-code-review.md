# Project Plan: Codebase Review & Hardening

## 1. Goal

Review the complete Hackathon codebase (Python backend, Flask web dashboard, Clarity smart contracts) to identify potential issues, security holes, and simulated logic, and plan the transition from a hackathon prototype to a production-ready application.

## 2. Issues Discovered (Debug Analysis)

### Hypothesis 1: Simulated Analytics (High Priority)

- **Finding**: In `enhanced_fraud_detector.py`, functions like `_analyze_structure`, `_analyze_content`, `_analyze_metadata`, `_statistical_analysis`, and `_digital_forensics_analysis` use `np.random.uniform()` to generate simulated scores.
- **Impact**: It doesn't actually detect fraud accurately; it mocks the functionality.

### Hypothesis 2: Hardcoded Configurations & Secrets (Medium Priority)

- **Finding**: In `app.py`, the Firebase credentials path is hardcoded (`Models/serviceAccountKey.json`). Flask secret key uses `secrets.token_hex(16)` per run, which invalidates all user sessions every time the app restarts.
- **Finding**: In multiple scripts (`pii_blockchain_integration.py`, `start_pii_blockchain_system.py`), URLs and ports (like `http://localhost:5001`, `5002`) are hardcoded instead of using environment variables.

### Hypothesis 3: Scalability & Performance Bottlenecks (Medium Priority)

- **Finding**: `transaction_monitor.py` and `stacks_client.py` continuously poll the Stacks API via `requests.get` every 2-3 seconds. This will easily hit API rate limits.
- **Finding**: `app.py` loads Heavy NLP models (`spacy`, `transformers`) globally on startup. This blocks the main thread and consumes heavy memory in a synchronous WSGI environment.

### Hypothesis 4: Smart Contract Considerations (Low Priority)

- **Finding**: `tokenization-system.clar` uses an `emergency-pause` function but it merely prints an event. It does not actually pause the transfer or minting capabilities.

## 3. Task Breakdown (Implementation Plan)

### Phase 1: Configuration & Environment Setup

- [ ] Move hardcoded URLs, ports, and Firebase credential paths into a `.env` file.
- [ ] Set a persistent Flask `SECRET_KEY` via environment variables.

### Phase 2: Fraud Detection Implementation

- [ ] Replace `np.random.uniform()` in `enhanced_fraud_detector.py` with actual logic (e.g., proper metadata extraction via `PyPDF2`/`fitz`, real ML models for image forensics instead of random numbers).

### Phase 3: Performance & Scalability Optimization

- [ ] Implement exponential backoff or use Stacks WebSockets (if available) instead of aggressive 2-second polling in `stacks_client.py`.
- [ ] Move large model loading (Transformers/Spacy) into background workers (e.g., Celery) to prevent blocking the Flask app on startup or during API calls.

### Phase 4: Smart Contract Hardening

- [ ] Implement an actual `is-paused` data variable in `tokenization-system.clar` and assert it is `false` in critical functions like `transfer`, `mint-tokens`, and `burn-tokens`.

## 4. Verification Checklist

- [ ] End-to-end test of uploading a document without random scores.
- [ ] Ensure Stacks API is not rate-limiting the monitor.
- [ ] Ensure `emergency-pause` actually stops token transfers on a local devnet.
