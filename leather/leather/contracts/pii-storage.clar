;; PII Tracking Smart Contract
;; This contract handles adding and tracking PII data with transaction visibility

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u1))
(define-constant ERR-INVALID-PII-DATA (err u2))
(define-constant ERR-PII-NOT-FOUND (err u3))
(define-constant ERR-ALREADY-EXISTS (err u4))
(define-constant ERR-INVALID-HASH (err u5))

;; Contract owner
(define-constant CONTRACT-OWNER tx-sender)

;; Data structure for PII records
(define-map pii-records 
  { pii-id: uint }
  {
    data-hash: (buff 32),          ;; SHA256 hash of PII data (not storing actual PII)
    owner: principal,              ;; Who owns this PII record
    timestamp: uint,               ;; Block height when added
    is-active: bool,               ;; Whether the record is active
    access-count: uint,            ;; How many times it was accessed
    metadata: (string-ascii 256)   ;; Additional metadata
  }
)

;; Transaction log for PII operations
(define-map transaction-log
  { tx-id: uint }
  {
    operation: (string-ascii 50),  ;; Type of operation (add, view, update, delete)
    pii-id: uint,                  ;; PII record ID involved
    user: principal,               ;; User who performed the operation
    block-height: uint,            ;; When the transaction occurred
    details: (string-ascii 500)    ;; Additional transaction details
  }
)

;; Counter for PII IDs
(define-data-var pii-counter uint u0)

;; Counter for transaction IDs
(define-data-var tx-counter uint u0)

;; Authorized users who can add PII
(define-map authorized-users { user: principal } { is-authorized: bool })

;; Initialize contract owner as authorized
(map-set authorized-users { user: CONTRACT-OWNER } { is-authorized: true })

;; Helper function to get next PII ID
(define-private (get-next-pii-id)
  (let ((current-id (var-get pii-counter)))
    (var-set pii-counter (+ current-id u1))
    (+ current-id u1)
  )
)

;; Helper function to get next transaction ID
(define-private (get-next-tx-id)
  (let ((current-id (var-get tx-counter)))
    (var-set tx-counter (+ current-id u1))
    (+ current-id u1)
  )
)

;; Helper function to log transactions
(define-private (log-transaction (operation (string-ascii 50)) (pii-id uint) (details (string-ascii 500)))
  (let ((tx-id (get-next-tx-id)))
    (map-set transaction-log
      { tx-id: tx-id }
      {
        operation: operation,
        pii-id: pii-id,
        user: tx-sender,
        block-height: stacks-block-height,
        details: details
      }
    )
    tx-id
  )
)

;; Add authorized user (only contract owner can do this)
(define-public (add-authorized-user (user principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set authorized-users { user: user } { is-authorized: true })
    (ok true)
  )
)

;; Remove authorized user (only contract owner can do this)
(define-public (remove-authorized-user (user principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set authorized-users { user: user } { is-authorized: false })
    (ok true)
  )
)

;; Check if user is authorized
(define-read-only (is-authorized (user principal))
  (default-to false (get is-authorized (map-get? authorized-users { user: user })))
)

;; Add PII record (only authorized users)
(define-public (add-pii-record (data-hash (buff 32)) (metadata (string-ascii 256)))
  (let (
    (pii-id (get-next-pii-id))
    (is-user-authorized (is-authorized tx-sender))
  )
    (asserts! is-user-authorized ERR-NOT-AUTHORIZED)
    (asserts! (> (len data-hash) u0) ERR-INVALID-PII-DATA)
    
    ;; Store the PII record (hash uniqueness check simplified for demo)
    (asserts! (not (hash-exists data-hash)) ERR-ALREADY-EXISTS)
    
    ;; Store the PII record
    (map-set pii-records
      { pii-id: pii-id }
      {
        data-hash: data-hash,
        owner: tx-sender,
        timestamp: stacks-block-height,
        is-active: true,
        access-count: u0,
        metadata: metadata
      }
    )
    
    ;; Log the transaction
    (log-transaction "add" pii-id (concat "Added PII record with metadata: " metadata))
    
    (ok pii-id)
  )
)

;; Get PII record by ID
(define-read-only (get-pii-record (pii-id uint))
  (map-get? pii-records { pii-id: pii-id })
)

;; Simple hash existence check (checks first few records - simplified for demo)
(define-read-only (hash-exists (search-hash (buff 32)))
  ;; Simplified check - in production you'd want proper indexing
  (let ((record1 (get-pii-record u1))
        (record2 (get-pii-record u2))
        (record3 (get-pii-record u3)))
    (or 
      (and (is-some record1) (is-eq (get data-hash (unwrap-panic record1)) search-hash))
      (and (is-some record2) (is-eq (get data-hash (unwrap-panic record2)) search-hash))
      (and (is-some record3) (is-eq (get data-hash (unwrap-panic record3)) search-hash))
    )
  )
)

;; Update PII record access count and log access
(define-public (access-pii-record (pii-id uint))
  (let (
    (existing-record (unwrap! (get-pii-record pii-id) ERR-PII-NOT-FOUND))
    (is-owner (is-eq tx-sender (get owner existing-record)))
    (is-user-authorized (is-authorized tx-sender))
  )
    (asserts! (or is-owner is-user-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (get is-active existing-record) ERR-PII-NOT-FOUND)
    
    ;; Update access count
    (map-set pii-records
      { pii-id: pii-id }
      (merge existing-record { access-count: (+ (get access-count existing-record) u1) })
    )
    
    ;; Log the access
    (log-transaction "access" pii-id "PII record accessed")
    
    (ok existing-record)
  )
)

;; Deactivate PII record (soft delete)
(define-public (deactivate-pii-record (pii-id uint))
  (let (
    (existing-record (unwrap! (get-pii-record pii-id) ERR-PII-NOT-FOUND))
    (is-owner (is-eq tx-sender (get owner existing-record)))
  )
    (asserts! (or is-owner (is-eq tx-sender CONTRACT-OWNER)) ERR-NOT-AUTHORIZED)
    
    ;; Deactivate the record
    (map-set pii-records
      { pii-id: pii-id }
      (merge existing-record { is-active: false })
    )
    
    ;; Log the deactivation
    (log-transaction "deactivate" pii-id "PII record deactivated")
    
    (ok true)
  )
)

;; Get transaction log entry
(define-read-only (get-transaction (tx-id uint))
  (map-get? transaction-log { tx-id: tx-id })
)

;; Get all transactions for a specific PII record (simplified version)
(define-read-only (get-pii-transactions (pii-id uint))
  (let ((max-tx-id (var-get tx-counter)))
    ;; In a real implementation, you'd want a more efficient way to query this
    ;; This is a simplified version for demonstration
    (list 
      (get-transaction u1)
      (get-transaction u2)
      (get-transaction u3)
      (get-transaction u4)
      (get-transaction u5)
    )
  )
)

;; Verify PII data hash
(define-public (verify-pii-hash (pii-id uint) (provided-hash (buff 32)))
  (let (
    (existing-record (unwrap! (get-pii-record pii-id) ERR-PII-NOT-FOUND))
    (is-owner (is-eq tx-sender (get owner existing-record)))
    (is-user-authorized (is-authorized tx-sender))
  )
    (asserts! (or is-owner is-user-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (get is-active existing-record) ERR-PII-NOT-FOUND)
    
    (let ((hash-matches (is-eq (get data-hash existing-record) provided-hash)))
      ;; Log the verification attempt
      (log-transaction "verify" pii-id 
        (if hash-matches "Hash verification successful" "Hash verification failed"))
      
      (ok hash-matches)
    )
  )
)

;; Get contract statistics
(define-read-only (get-contract-stats)
  {
    total-pii-records: (var-get pii-counter),
    total-transactions: (var-get tx-counter),
    contract-owner: CONTRACT-OWNER
  }
)

;; Get user's PII records count (simplified)
(define-read-only (get-user-pii-count (user principal))
  ;; In a real implementation, you'd maintain a separate map for this
  ;; This is a placeholder that returns 0
  u0
)