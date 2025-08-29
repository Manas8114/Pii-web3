;; ===========================================
;; PII DATA STORAGE SMART CONTRACT
;; ===========================================
;; Privacy-focused contract for storing tokenized PII data
;; Integrates with Standard Chartered document processing system

;; Contract owner
(define-constant contract-owner tx-sender)

;; Error constants
(define-constant err-owner-only (err u200))
(define-constant err-unauthorized (err u201))
(define-constant err-record-not-found (err u202))
(define-constant err-invalid-data (err u203))
(define-constant err-duplicate-token (err u204))

;; Data structures
(define-map pii-records
    { record-id: uint }
    {
        safe-token: (string-ascii 64),
        entity-type: (string-ascii 50),
        confidence-score: uint,
        document-hash: (string-ascii 128),
        timestamp: uint,
        block-height: uint,
        processor-address: principal,
        is-sensitive: bool,
        metadata: (string-ascii 500)
    }
)

(define-map token-to-record
    { safe-token: (string-ascii 64) }
    { record-id: uint }
)

(define-map document-records
    { document-hash: (string-ascii 128) }
    { 
        total-records: uint,
        sensitive-count: uint,
        processor: principal,
        timestamp: uint
    }
)

(define-map audit-log
    { audit-id: uint }
    {
        action: (string-ascii 50),
        record-id: uint,
        actor: principal,
        timestamp: uint,
        metadata: (string-ascii 200)
    }
)

;; Global counters
(define-data-var record-counter uint u0)
(define-data-var audit-counter uint u0)
(define-data-var total-documents uint u0)

;; Events for real-time monitoring
(define-public (emit-pii-stored (record-id uint) (entity-type (string-ascii 50)) (is-sensitive bool) (document-hash (string-ascii 128)))
    (begin
        (print {
            event: "pii-stored",
            record-id: record-id,
            entity-type: entity-type,
            is-sensitive: is-sensitive,
            document-hash: document-hash,
            processor: tx-sender,
            timestamp: block-timestamp,
            block-height: block-height
        })
        (ok true)
    )
)

(define-public (emit-document-processed (document-hash (string-ascii 128)) (total-pii uint) (sensitive-count uint))
    (begin
        (print {
            event: "document-processed",
            document-hash: document-hash,
            total-pii-found: total-pii,
            sensitive-count: sensitive-count,
            processor: tx-sender,
            timestamp: block-timestamp
        })
        (ok true)
    )
)

;; Store PII data record
(define-public (store-pii-record 
    (safe-token (string-ascii 64)) 
    (entity-type (string-ascii 50)) 
    (confidence-score uint) 
    (document-hash (string-ascii 128))
    (is-sensitive bool)
    (metadata (string-ascii 500))
)
    (let 
        (
            (new-record-id (+ (var-get record-counter) u1))
        )
        (begin
            ;; Check if token already exists
            (asserts! (is-none (map-get? token-to-record { safe-token: safe-token })) err-duplicate-token)
            
            ;; Store PII record
            (map-set pii-records
                { record-id: new-record-id }
                {
                    safe-token: safe-token,
                    entity-type: entity-type,
                    confidence-score: confidence-score,
                    document-hash: document-hash,
                    timestamp: block-timestamp,
                    block-height: block-height,
                    processor-address: tx-sender,
                    is-sensitive: is-sensitive,
                    metadata: metadata
                }
            )
            
            ;; Create token mapping
            (map-set token-to-record
                { safe-token: safe-token }
                { record-id: new-record-id }
            )
            
            ;; Update document statistics
            (update-document-stats document-hash is-sensitive)
            
            ;; Log the action
            (log-audit-action "STORE_PII" new-record-id "PII record stored")
            
            ;; Update counter
            (var-set record-counter new-record-id)
            
            ;; Emit event
            (try! (emit-pii-stored new-record-id entity-type is-sensitive document-hash))
            
            (ok new-record-id)
        )
    )
)

;; Store multiple PII records from document processing
(define-public (store-document-pii-batch 
    (document-hash (string-ascii 128))
    (pii-data (list 20 {
        safe-token: (string-ascii 64),
        entity-type: (string-ascii 50),
        confidence-score: uint,
        is-sensitive: bool,
        metadata: (string-ascii 500)
    }))
)
    (let 
        (
            (stored-count (fold store-single-pii-record pii-data { 
                document-hash: document-hash, 
                count: u0,
                sensitive-count: u0 
            }))
        )
        (begin
            ;; Emit document processed event
            (try! (emit-document-processed 
                document-hash 
                (get count stored-count)
                (get sensitive-count stored-count)
            ))
            
            ;; Update total documents counter
            (var-set total-documents (+ (var-get total-documents) u1))
            
            (ok stored-count)
        )
    )
)

;; Helper function for batch processing
(define-private (store-single-pii-record 
    (pii-item {
        safe-token: (string-ascii 64),
        entity-type: (string-ascii 50),
        confidence-score: uint,
        is-sensitive: bool,
        metadata: (string-ascii 500)
    })
    (acc {
        document-hash: (string-ascii 128),
        count: uint,
        sensitive-count: uint
    })
)
    (let
        (
            (storage-result (store-pii-record 
                (get safe-token pii-item)
                (get entity-type pii-item)
                (get confidence-score pii-item)
                (get document-hash acc)
                (get is-sensitive pii-item)
                (get metadata pii-item)
            ))
        )
        (if (is-ok storage-result)
            {
                document-hash: (get document-hash acc),
                count: (+ (get count acc) u1),
                sensitive-count: (+ (get sensitive-count acc) (if (get is-sensitive pii-item) u1 u0))
            }
            acc
        )
    )
)

;; Update document processing statistics
(define-private (update-document-stats (document-hash (string-ascii 128)) (is-sensitive bool))
    (let
        (
            (current-stats (default-to 
                { total-records: u0, sensitive-count: u0, processor: tx-sender, timestamp: block-timestamp }
                (map-get? document-records { document-hash: document-hash })
            ))
        )
        (map-set document-records
            { document-hash: document-hash }
            {
                total-records: (+ (get total-records current-stats) u1),
                sensitive-count: (+ (get sensitive-count current-stats) (if is-sensitive u1 u0)),
                processor: tx-sender,
                timestamp: block-timestamp
            }
        )
    )
)

;; Get PII record by safe token
(define-read-only (get-pii-by-token (safe-token (string-ascii 64)))
    (let
        (
            (record-mapping (map-get? token-to-record { safe-token: safe-token }))
        )
        (match record-mapping
            record-data (map-get? pii-records { record-id: (get record-id record-data) })
            none
        )
    )
)

;; Get PII record by ID
(define-read-only (get-pii-record (record-id uint))
    (map-get? pii-records { record-id: record-id })
)

;; Get document statistics
(define-read-only (get-document-stats (document-hash (string-ascii 128)))
    (map-get? document-records { document-hash: document-hash })
)

;; Get recent PII records
(define-read-only (get-recent-pii-records (count uint))
    (let
        (
            (current-counter (var-get record-counter))
            (start-id (if (> current-counter count) (- current-counter count) u0))
        )
        (map get-pii-record (list start-id))
    )
)

;; Get system statistics
(define-read-only (get-system-stats)
    {
        total-pii-records: (var-get record-counter),
        total-documents: (var-get total-documents),
        total-audit-entries: (var-get audit-counter)
    }
)

;; Privacy functions - Get record without sensitive data
(define-read-only (get-pii-record-public (record-id uint))
    (match (map-get? pii-records { record-id: record-id })
        record-data {
            record-id: record-id,
            entity-type: (get entity-type record-data),
            confidence-score: (get confidence-score record-data),
            timestamp: (get timestamp record-data),
            block-height: (get block-height record-data),
            is-sensitive: (get is-sensitive record-data)
        }
        none
    )
)

;; Audit logging
(define-private (log-audit-action (action (string-ascii 50)) (record-id uint) (metadata (string-ascii 200)))
    (let
        (
            (new-audit-id (+ (var-get audit-counter) u1))
        )
        (begin
            (map-set audit-log
                { audit-id: new-audit-id }
                {
                    action: action,
                    record-id: record-id,
                    actor: tx-sender,
                    timestamp: block-timestamp,
                    metadata: metadata
                }
            )
            
            (var-set audit-counter new-audit-id)
            
            (print {
                event: "audit-log",
                audit-id: new-audit-id,
                action: action,
                record-id: record-id,
                actor: tx-sender,
                timestamp: block-timestamp
            })
            
            new-audit-id
        )
    )
)

;; Get audit logs
(define-read-only (get-audit-log (audit-id uint))
    (map-get? audit-log { audit-id: audit-id })
)

;; Administrative functions
(define-public (update-record-metadata (record-id uint) (new-metadata (string-ascii 500)))
    (let
        (
            (record-data (unwrap! (map-get? pii-records { record-id: record-id }) err-record-not-found))
        )
        (begin
            ;; Only the processor or contract owner can update
            (asserts! 
                (or (is-eq tx-sender (get processor-address record-data)) (is-eq tx-sender contract-owner)) 
                err-unauthorized
            )
            
            (map-set pii-records
                { record-id: record-id }
                (merge record-data { metadata: new-metadata })
            )
            
            ;; Log the update
            (log-audit-action "UPDATE_METADATA" record-id "Metadata updated")
            
            (ok true)
        )
    )
)

;; Emergency functions (contract owner only)
(define-public (emergency-pause)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (print { event: "emergency-pause", timestamp: block-timestamp })
        (ok true)
    )
)

;; Get counters
(define-read-only (get-record-counter)
    (var-get record-counter)
)

(define-read-only (get-audit-counter)
    (var-get audit-counter)
)

;; Contract initialization
(print "✅ PII Storage System Smart Contract Deployed Successfully!")
(print { 
    contract: "pii-storage-system",
    version: "1.0.0",
    deployed-by: tx-sender,
    timestamp: block-timestamp,
    block-height: block-height,
    privacy-enabled: true
})
