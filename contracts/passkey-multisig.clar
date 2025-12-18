;; Passkey-Protected Multisig - Clarity 4
;; A multisig wallet where each signer uses biometrics/passkeys
;;
;; Clarity 4 Features Used:
;; - secp256r1-verify: Verify passkey signatures from each signer
;; - stacks-block-time: Time-bound approvals and expiration
;; - to-ascii?: Human-readable transaction descriptions

;; ============================================
;; CONSTANTS
;; ============================================

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u5001))
(define-constant ERR_INVALID_SIGNATURE (err u5002))
(define-constant ERR_MULTISIG_NOT_FOUND (err u5003))
(define-constant ERR_TX_NOT_FOUND (err u5004))
(define-constant ERR_ALREADY_SIGNED (err u5005))
(define-constant ERR_TX_EXPIRED (err u5006))
(define-constant ERR_THRESHOLD_NOT_MET (err u5007))
(define-constant ERR_ALREADY_EXECUTED (err u5008))
(define-constant ERR_INVALID_THRESHOLD (err u5009))
(define-constant ERR_NOT_SIGNER (err u5010))
(define-constant ERR_MAX_SIGNERS (err u5011))

;; Transaction expiration: 7 days
(define-constant TX_EXPIRATION u604800)

;; Maximum signers
(define-constant MAX_SIGNERS u10)

;; ============================================
;; DATA STRUCTURES
;; ============================================

;; Multisig wallets
(define-map multisigs
  { multisig-id: (buff 32) }
  {
    name: (string-ascii 64),
    threshold: uint,
    signer-count: uint,
    created-at: uint,
    nonce: uint,
    balance: uint
  }
)

;; Signers for each multisig (passkey public keys)
(define-map signers
  { multisig-id: (buff 32), signer-index: uint }
  {
    pubkey: (buff 33),
    name: (string-ascii 32),
    added-at: uint,
    is-active: bool
  }
)

;; Pending transactions
(define-map pending-txs
  { multisig-id: (buff 32), tx-id: uint }
  {
    proposer: (buff 33),
    tx-type: (string-ascii 20),
    recipient: (optional principal),
    amount: uint,
    data: (buff 256),
    created-at: uint,
    expires-at: uint,
    approval-count: uint,
    is-executed: bool,
    description: (string-ascii 100)
  }
)

;; Track who has signed each transaction
(define-map tx-approvals
  { multisig-id: (buff 32), tx-id: uint, signer-pubkey: (buff 33) }
  {
    signed-at: uint,
    signature: (buff 64)
  }
)

;; Multisig transaction counters
(define-map tx-counters
  { multisig-id: (buff 32) }
  { next-tx-id: uint }
)

;; ============================================
;; EVENTS (using print for monitoring)
;; ============================================

(define-private (log-multisig-created (multisig-id (buff 32)) (name (string-ascii 64)) (threshold uint) (signer-count uint))
  (print {
    event: "multisig-created",
    multisig-id: multisig-id,
    name: name,
    threshold: threshold,
    signer-count: signer-count,
    timestamp: stacks-block-time
  })
)

(define-private (log-deposit (multisig-id (buff 32)) (amount uint) (sender principal))
  (print {
    event: "deposit",
    multisig-id: multisig-id,
    amount: amount,
    sender: sender,
    timestamp: stacks-block-time
  })
)

(define-private (log-tx-proposed (multisig-id (buff 32)) (tx-id uint) (proposer (buff 33)) (tx-type (string-ascii 20)) (amount uint))
  (print {
    event: "tx-proposed",
    multisig-id: multisig-id,
    tx-id: tx-id,
    proposer: proposer,
    tx-type: tx-type,
    amount: amount,
    timestamp: stacks-block-time
  })
)

(define-private (log-tx-approved (multisig-id (buff 32)) (tx-id uint) (signer (buff 33)) (approval-count uint))
  (print {
    event: "tx-approved",
    multisig-id: multisig-id,
    tx-id: tx-id,
    signer: signer,
    approval-count: approval-count,
    timestamp: stacks-block-time
  })
)

(define-private (log-tx-executed (multisig-id (buff 32)) (tx-id uint) (tx-type (string-ascii 20)) (amount uint))
  (print {
    event: "tx-executed",
    multisig-id: multisig-id,
    tx-id: tx-id,
    tx-type: tx-type,
    amount: amount,
    timestamp: stacks-block-time
  })
)

;; ============================================
;; READ-ONLY FUNCTIONS
;; ============================================

;; Get multisig details
(define-read-only (get-multisig (multisig-id (buff 32)))
  (map-get? multisigs { multisig-id: multisig-id })
)

;; Get signer info
(define-read-only (get-signer (multisig-id (buff 32)) (index uint))
  (map-get? signers { multisig-id: multisig-id, signer-index: index })
)

;; Get pending transaction
(define-read-only (get-pending-tx (multisig-id (buff 32)) (tx-id uint))
  (map-get? pending-txs { multisig-id: multisig-id, tx-id: tx-id })
)

;; Check if signer has approved
(define-read-only (has-signed (multisig-id (buff 32)) (tx-id uint) (pubkey (buff 33)))
  (is-some (map-get? tx-approvals { multisig-id: multisig-id, tx-id: tx-id, signer-pubkey: pubkey }))
)

;; Get current time
(define-read-only (get-current-time)
  stacks-block-time
)

;; Check if transaction is still valid
(define-read-only (is-tx-valid (multisig-id (buff 32)) (tx-id uint))
  (match (map-get? pending-txs { multisig-id: multisig-id, tx-id: tx-id })
    tx (and (not (get is-executed tx))
            (< stacks-block-time (get expires-at tx)))
    false
  )
)

;; Generate transaction summary using to-ascii?
(define-read-only (generate-tx-summary 
    (multisig-id (buff 32))
    (tx-id uint)
    (tx-type (string-ascii 20))
    (amount uint)
  )
  (let
    (
      (tx-id-str (unwrap-panic (to-ascii? tx-id)))
      (amount-str (unwrap-panic (to-ascii? amount)))
      (time-str (unwrap-panic (to-ascii? stacks-block-time)))
    )
    (concat "MULTISIG_TX|ID:"
      (concat tx-id-str
        (concat "|TYPE:"
          (concat tx-type
            (concat "|AMOUNT:"
              (concat amount-str
                (concat "|TIME:" time-str)
              )
            )
          )
        )
      )
    )
  )
)

;; Check if pubkey is a valid signer (read-only, checks up to 10 signers)
(define-read-only (is-valid-signer (multisig-id (buff 32)) (pubkey (buff 33)))
  (or
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u0 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u1 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u2 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u3 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u4 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u5 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u6 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u7 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u8 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
    (match (map-get? signers { multisig-id: multisig-id, signer-index: u9 }) s (and (is-eq (get pubkey s) pubkey) (get is-active s)) false)
  )
)

;; ============================================
;; PUBLIC FUNCTIONS
;; ============================================

;; Create a new passkey multisig
(define-public (create-multisig
    (multisig-id (buff 32))
    (name (string-ascii 64))
    (threshold uint)
    (initial-signers (list 10 (buff 33)))
  )
  (let
    (
      (signer-count (len initial-signers))
    )
    ;; Validate threshold
    (asserts! (> threshold u0) ERR_INVALID_THRESHOLD)
    (asserts! (<= threshold signer-count) ERR_INVALID_THRESHOLD)
    (asserts! (<= signer-count MAX_SIGNERS) ERR_MAX_SIGNERS)
    
    ;; Create multisig
    (map-set multisigs
      { multisig-id: multisig-id }
      {
        name: name,
        threshold: threshold,
        signer-count: signer-count,
        created-at: stacks-block-time,
        nonce: u0,
        balance: u0
      }
    )
    
    ;; Initialize tx counter
    (map-set tx-counters
      { multisig-id: multisig-id }
      { next-tx-id: u1 }
    )
    
    ;; Add signers
    (add-signers-batch multisig-id initial-signers u0)

    ;; Log event
    (log-multisig-created multisig-id name threshold signer-count)

    (ok multisig-id)
  )
)

;; Helper to add signers
(define-private (add-signers-batch (multisig-id (buff 32)) (pubkeys (list 10 (buff 33))) (start-index uint))
  (fold add-signer-iter pubkeys { multisig-id: multisig-id, index: start-index })
)

(define-private (add-signer-iter 
    (pubkey (buff 33)) 
    (acc { multisig-id: (buff 32), index: uint })
  )
  (begin
    (map-set signers
      { multisig-id: (get multisig-id acc), signer-index: (get index acc) }
      {
        pubkey: pubkey,
        name: "Signer",
        added-at: stacks-block-time,
        is-active: true
      }
    )
    { multisig-id: (get multisig-id acc), index: (+ (get index acc) u1) }
  )
)

;; Deposit STX to multisig
(define-public (deposit (multisig-id (buff 32)) (amount uint))
  (let
    (
      (multisig (unwrap! (map-get? multisigs { multisig-id: multisig-id }) ERR_MULTISIG_NOT_FOUND))
    )
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    (map-set multisigs
      { multisig-id: multisig-id }
      (merge multisig { balance: (+ (get balance multisig) amount) })
    )

    ;; Log event
    (log-deposit multisig-id amount tx-sender)

    (ok amount)
  )
)

;; Propose a transaction (any signer can propose)
(define-public (propose-tx
    (multisig-id (buff 32))
    (tx-type (string-ascii 20))
    (recipient (optional principal))
    (amount uint)
    (description (string-ascii 100))
    (message-hash (buff 32))
    (signature (buff 64))
    (proposer-pubkey (buff 33))
  )
  (let
    (
      (multisig (unwrap! (map-get? multisigs { multisig-id: multisig-id }) ERR_MULTISIG_NOT_FOUND))
      (tx-counter (default-to { next-tx-id: u1 } (map-get? tx-counters { multisig-id: multisig-id })))
      (tx-id (get next-tx-id tx-counter))
      (expires-at (+ stacks-block-time TX_EXPIRATION))
    )
    ;; Verify proposer is a valid signer
    (asserts! (is-valid-signer multisig-id proposer-pubkey) ERR_NOT_SIGNER)
    
    ;; Verify signature using secp256r1-verify (passkey)
    (asserts! (secp256r1-verify message-hash signature proposer-pubkey) ERR_INVALID_SIGNATURE)
    
    ;; Create pending transaction
    (map-set pending-txs
      { multisig-id: multisig-id, tx-id: tx-id }
      {
        proposer: proposer-pubkey,
        tx-type: tx-type,
        recipient: recipient,
        amount: amount,
        data: 0x,
        created-at: stacks-block-time,
        expires-at: expires-at,
        approval-count: u1,
        is-executed: false,
        description: description
      }
    )
    
    ;; Record proposer's approval
    (map-set tx-approvals
      { multisig-id: multisig-id, tx-id: tx-id, signer-pubkey: proposer-pubkey }
      {
        signed-at: stacks-block-time,
        signature: signature
      }
    )
    
    ;; Increment tx counter
    (map-set tx-counters
      { multisig-id: multisig-id }
      { next-tx-id: (+ tx-id u1) }
    )

    ;; Log event
    (log-tx-proposed multisig-id tx-id proposer-pubkey tx-type amount)

    (ok {
      tx-id: tx-id,
      expires-at: expires-at,
      summary: (generate-tx-summary multisig-id tx-id tx-type amount)
    })
  )
)

;; Approve a pending transaction
(define-public (approve-tx
    (multisig-id (buff 32))
    (tx-id uint)
    (message-hash (buff 32))
    (signature (buff 64))
    (signer-pubkey (buff 33))
  )
  (let
    (
      (multisig (unwrap! (map-get? multisigs { multisig-id: multisig-id }) ERR_MULTISIG_NOT_FOUND))
      (pending-tx (unwrap! (map-get? pending-txs { multisig-id: multisig-id, tx-id: tx-id }) ERR_TX_NOT_FOUND))
    )
    ;; Verify signer is valid
    (asserts! (is-valid-signer multisig-id signer-pubkey) ERR_NOT_SIGNER)
    
    ;; Verify not already signed
    (asserts! (not (has-signed multisig-id tx-id signer-pubkey)) ERR_ALREADY_SIGNED)
    
    ;; Verify tx is still valid
    (asserts! (< stacks-block-time (get expires-at pending-tx)) ERR_TX_EXPIRED)
    (asserts! (not (get is-executed pending-tx)) ERR_ALREADY_EXECUTED)
    
    ;; Verify signature using secp256r1-verify
    (asserts! (secp256r1-verify message-hash signature signer-pubkey) ERR_INVALID_SIGNATURE)
    
    ;; Record approval
    (map-set tx-approvals
      { multisig-id: multisig-id, tx-id: tx-id, signer-pubkey: signer-pubkey }
      {
        signed-at: stacks-block-time,
        signature: signature
      }
    )
    
    ;; Update approval count
    (let
      (
        (new-approval-count (+ (get approval-count pending-tx) u1))
      )
      (map-set pending-txs
        { multisig-id: multisig-id, tx-id: tx-id }
        (merge pending-tx { approval-count: new-approval-count })
      )

      ;; Log event
      (log-tx-approved multisig-id tx-id signer-pubkey new-approval-count)

      (ok new-approval-count)
    )
  )
)

;; Execute a transaction once threshold is met
(define-public (execute-tx (multisig-id (buff 32)) (tx-id uint))
  (let
    (
      (multisig (unwrap! (map-get? multisigs { multisig-id: multisig-id }) ERR_MULTISIG_NOT_FOUND))
      (pending-tx (unwrap! (map-get? pending-txs { multisig-id: multisig-id, tx-id: tx-id }) ERR_TX_NOT_FOUND))
      (threshold (get threshold multisig))
    )
    ;; Verify tx is valid
    (asserts! (< stacks-block-time (get expires-at pending-tx)) ERR_TX_EXPIRED)
    (asserts! (not (get is-executed pending-tx)) ERR_ALREADY_EXECUTED)
    
    ;; Verify threshold met
    (asserts! (>= (get approval-count pending-tx) threshold) ERR_THRESHOLD_NOT_MET)
    
    ;; Execute based on tx-type
    (if (is-eq (get tx-type pending-tx) "TRANSFER")
      (let
        (
          (recipient (unwrap! (get recipient pending-tx) ERR_TX_NOT_FOUND))
          (amount (get amount pending-tx))
        )
        ;; Transfer funds
        (try! (as-contract (stx-transfer? amount tx-sender recipient)))
        
        ;; Update balance
        (map-set multisigs
          { multisig-id: multisig-id }
          (merge multisig { balance: (- (get balance multisig) amount) })
        )
        true
      )
      true
    )
    
    ;; Mark as executed
    (map-set pending-txs
      { multisig-id: multisig-id, tx-id: tx-id }
      (merge pending-tx { is-executed: true })
    )

    ;; Log event
    (log-tx-executed multisig-id tx-id (get tx-type pending-tx) (get amount pending-tx))

    (ok true)
  )
)
