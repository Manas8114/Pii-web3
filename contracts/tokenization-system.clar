;; ===========================================
;; TOKENIZATION SYSTEM SMART CONTRACT
;; ===========================================
;; A comprehensive tokenization system with real-time transaction logging
;; Designed for Standard Chartered Hackathon - CodeFest 2025

;; Contract owner
(define-constant contract-owner tx-sender)

;; Error constants
(define-constant err-owner-only (err u100))
(define-constant err-insufficient-balance (err u101))
(define-constant err-token-not-found (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-amount (err u104))

;; Data structures
(define-map tokens 
    { token-id: uint } 
    {
        name: (string-ascii 100),
        symbol: (string-ascii 10),
        total-supply: uint,
        decimals: uint,
        owner: principal,
        created-at: uint,
        metadata: (string-ascii 500)
    }
)

(define-map balances 
    { token-id: uint, holder: principal } 
    { balance: uint }
)

(define-map transaction-log
    { tx-id: uint }
    {
        from: (optional principal),
        to: principal,
        token-id: uint,
        amount: uint,
        tx-type: (string-ascii 20),
        timestamp: uint,
        block-height: uint,
        metadata: (string-ascii 200)
    }
)

;; Global counters
(define-data-var token-counter uint u0)
(define-data-var transaction-counter uint u0)

;; Events for real-time monitoring
(define-public (emit-token-created (token-id uint) (name (string-ascii 100)) (symbol (string-ascii 10)))
    (begin
        (print {
            event: "token-created",
            token-id: token-id,
            name: name,
            symbol: symbol,
            creator: tx-sender,
            timestamp: block-timestamp,
            block-height: block-height
        })
        (ok true)
    )
)

(define-public (emit-transaction (tx-id uint) (from (optional principal)) (to principal) (amount uint) (token-id uint))
    (begin
        (print {
            event: "transaction",
            tx-id: tx-id,
            from: from,
            to: to,
            amount: amount,
            token-id: token-id,
            timestamp: block-timestamp,
            block-height: block-height
        })
        (ok true)
    )
)

;; Create a new token
(define-public (create-token (name (string-ascii 100)) (symbol (string-ascii 10)) (total-supply uint) (decimals uint) (metadata (string-ascii 500)))
    (let 
        (
            (new-token-id (+ (var-get token-counter) u1))
        )
        (begin
            ;; Store token information
            (map-set tokens
                { token-id: new-token-id }
                {
                    name: name,
                    symbol: symbol,
                    total-supply: total-supply,
                    decimals: decimals,
                    owner: tx-sender,
                    created-at: block-timestamp,
                    metadata: metadata
                }
            )
            
            ;; Set initial balance to creator
            (map-set balances
                { token-id: new-token-id, holder: tx-sender }
                { balance: total-supply }
            )
            
            ;; Log creation transaction
            (log-transaction 
                none
                tx-sender
                new-token-id
                total-supply
                "CREATE"
                (concat "Created token: " name)
            )
            
            ;; Update counter
            (var-set token-counter new-token-id)
            
            ;; Emit event
            (try! (emit-token-created new-token-id name symbol))
            
            (ok new-token-id)
        )
    )
)

;; Transfer tokens
(define-public (transfer (token-id uint) (amount uint) (recipient principal))
    (let
        (
            (sender-balance (default-to u0 (get balance (map-get? balances { token-id: token-id, holder: tx-sender }))))
        )
        (asserts! (>= sender-balance amount) err-insufficient-balance)
        (asserts! (> amount u0) err-invalid-amount)
        
        (begin
            ;; Update sender balance
            (map-set balances
                { token-id: token-id, holder: tx-sender }
                { balance: (- sender-balance amount) }
            )
            
            ;; Update recipient balance
            (let 
                (
                    (recipient-balance (default-to u0 (get balance (map-get? balances { token-id: token-id, holder: recipient }))))
                )
                (map-set balances
                    { token-id: token-id, holder: recipient }
                    { balance: (+ recipient-balance amount) }
                )
            )
            
            ;; Log transaction
            (log-transaction
                (some tx-sender)
                recipient
                token-id
                amount
                "TRANSFER"
                "Token transfer"
            )
            
            ;; Emit event
            (try! (emit-transaction (var-get transaction-counter) (some tx-sender) recipient amount token-id))
            
            (ok true)
        )
    )
)

;; Mint new tokens (only token owner)
(define-public (mint-tokens (token-id uint) (amount uint) (recipient principal))
    (let
        (
            (token-info (unwrap! (map-get? tokens { token-id: token-id }) err-token-not-found))
        )
        (asserts! (is-eq tx-sender (get owner token-info)) err-unauthorized)
        
        (begin
            ;; Update total supply
            (map-set tokens
                { token-id: token-id }
                (merge token-info { total-supply: (+ (get total-supply token-info) amount) })
            )
            
            ;; Update recipient balance
            (let
                (
                    (current-balance (default-to u0 (get balance (map-get? balances { token-id: token-id, holder: recipient }))))
                )
                (map-set balances
                    { token-id: token-id, holder: recipient }
                    { balance: (+ current-balance amount) }
                )
            )
            
            ;; Log transaction
            (log-transaction
                none
                recipient
                token-id
                amount
                "MINT"
                "Tokens minted"
            )
            
            ;; Emit event
            (try! (emit-transaction (var-get transaction-counter) none recipient amount token-id))
            
            (ok true)
        )
    )
)

;; Burn tokens
(define-public (burn-tokens (token-id uint) (amount uint))
    (let
        (
            (sender-balance (default-to u0 (get balance (map-get? balances { token-id: token-id, holder: tx-sender }))))
            (token-info (unwrap! (map-get? tokens { token-id: token-id }) err-token-not-found))
        )
        (asserts! (>= sender-balance amount) err-insufficient-balance)
        
        (begin
            ;; Update sender balance
            (map-set balances
                { token-id: token-id, holder: tx-sender }
                { balance: (- sender-balance amount) }
            )
            
            ;; Update total supply
            (map-set tokens
                { token-id: token-id }
                (merge token-info { total-supply: (- (get total-supply token-info) amount) })
            )
            
            ;; Log transaction
            (log-transaction
                (some tx-sender)
                tx-sender
                token-id
                amount
                "BURN"
                "Tokens burned"
            )
            
            ;; Emit event
            (try! (emit-transaction (var-get transaction-counter) (some tx-sender) tx-sender amount token-id))
            
            (ok true)
        )
    )
)

;; Internal function to log transactions
(define-private (log-transaction (from (optional principal)) (to principal) (token-id uint) (amount uint) (tx-type (string-ascii 20)) (metadata (string-ascii 200)))
    (let
        (
            (new-tx-id (+ (var-get transaction-counter) u1))
        )
        (begin
            (map-set transaction-log
                { tx-id: new-tx-id }
                {
                    from: from,
                    to: to,
                    token-id: token-id,
                    amount: amount,
                    tx-type: tx-type,
                    timestamp: block-timestamp,
                    block-height: block-height,
                    metadata: metadata
                }
            )
            
            (var-set transaction-counter new-tx-id)
            
            ;; Print for real-time monitoring
            (print {
                event: "transaction-logged",
                tx-id: new-tx-id,
                from: from,
                to: to,
                token-id: token-id,
                amount: amount,
                tx-type: tx-type,
                timestamp: block-timestamp,
                block-height: block-height,
                metadata: metadata
            })
            
            new-tx-id
        )
    )
)

;; Read-only functions for querying
(define-read-only (get-token-info (token-id uint))
    (map-get? tokens { token-id: token-id })
)

(define-read-only (get-balance (token-id uint) (holder principal))
    (default-to u0 (get balance (map-get? balances { token-id: token-id, holder: holder })))
)

(define-read-only (get-transaction (tx-id uint))
    (map-get? transaction-log { tx-id: tx-id })
)

(define-read-only (get-token-counter)
    (var-get token-counter)
)

(define-read-only (get-transaction-counter)
    (var-get transaction-counter)
)

;; Get recent transactions (last N transactions)
(define-read-only (get-recent-transactions (count uint))
    (let
        (
            (current-counter (var-get transaction-counter))
            (start-id (if (> current-counter count) (- current-counter count) u0))
        )
        (map get-transaction-details (list start-id))
    )
)

(define-private (get-transaction-details (tx-id uint))
    (map-get? transaction-log { tx-id: tx-id })
)

;; Administrative functions
(define-public (update-token-metadata (token-id uint) (new-metadata (string-ascii 500)))
    (let
        (
            (token-info (unwrap! (map-get? tokens { token-id: token-id }) err-token-not-found))
        )
        (asserts! (is-eq tx-sender (get owner token-info)) err-unauthorized)
        
        (begin
            (map-set tokens
                { token-id: token-id }
                (merge token-info { metadata: new-metadata })
            )
            
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

;; Contract initialization
(print "✅ Tokenization System Smart Contract Deployed Successfully!")
(print { 
    contract: "tokenization-system",
    version: "1.0.0",
    deployed-by: tx-sender,
    timestamp: block-timestamp,
    block-height: block-height
})
