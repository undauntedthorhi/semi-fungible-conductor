;; looppulse-core
;; 
;; A smart contract that manages health data storage, access controls, and data sharing permissions
;; for the LoopPulse Health Monitor platform. This contract enables users to securely store their
;; health metrics and selectively share this data with healthcare providers and applications,
;; while maintaining complete ownership and control over their information.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u1001))
(define-constant ERR-USER-NOT-FOUND (err u1002))
(define-constant ERR-PROVIDER-NOT-REGISTERED (err u1003))
(define-constant ERR-DATA-NOT-FOUND (err u1004))
(define-constant ERR-PERMISSION-NOT-FOUND (err u1005))
(define-constant ERR-PERMISSION-EXPIRED (err u1006))
(define-constant ERR-INVALID-PARAMETERS (err u1007))
(define-constant ERR-ALREADY-REGISTERED (err u1008))
(define-constant ERR-INSUFFICIENT-PRIVILEGES (err u1009))
(define-constant ERR-EMERGENCY-ACCESS-NOT-ENABLED (err u1010))

;; Data structures

;; User profile information
(define-map users 
  { user: principal }
  {
    registered: bool,
    emergency-contact: (optional principal),
    emergency-access-enabled: bool,
    encrypted-profile-data-url: (optional (string-utf8 256))
  }
)

;; Healthcare provider information
(define-map healthcare-providers
  { provider: principal }
  {
    registered: bool,
    provider-name: (string-utf8 100),
    provider-type: (string-utf8 50),
    verification-status: bool,
    verification-date: (optional uint)
  }
)

;; Health data records
(define-map health-data
  { user: principal, data-id: uint }
  {
    data-type: (string-utf8 50),
    timestamp: uint,
    encrypted-data: (string-utf8 1024),
    large-data-url: (optional (string-utf8 256)),
    checksum: (string-utf8 64),
    provider: (optional principal)
  }
)

;; User's data access permissions for providers/applications
(define-map data-permissions
  { user: principal, accessor: principal, permission-id: uint }
  {
    granted-at: uint,
    expires-at: (optional uint),
    data-types: (list 20 (string-utf8 50)),
    revoked: bool,
    is-emergency-access: bool
  }
)

;; Data access logs
(define-map access-logs
  { user: principal, log-id: uint }
  {
    accessor: principal,
    timestamp: uint,
    data-types-accessed: (list 20 (string-utf8 50)),
    permission-id: uint
  }
)

;; Variables for ID tracking
(define-data-var next-data-id uint u0)
(define-data-var next-permission-id uint u0)
(define-data-var next-log-id uint u0)

;; Private functions

;; Get the next data ID for a user and increment the counter
(define-private (get-next-data-id)
  (let ((current-id (var-get next-data-id)))
    (var-set next-data-id (+ current-id u1))
    current-id
  )
)

;; Get the next permission ID and increment the counter
(define-private (get-next-permission-id)
  (let ((current-id (var-get next-permission-id)))
    (var-set next-permission-id (+ current-id u1))
    current-id
  )
)

;; Get the next log ID and increment the counter
(define-private (get-next-log-id)
  (let ((current-id (var-get next-log-id)))
    (var-set next-log-id (+ current-id u1))
    current-id
  )
)

;; Check if a user is registered
(define-private (is-user-registered (user principal))
  (default-to false (get registered (map-get? users { user: user })))
)

;; Check if a provider is registered
(define-private (is-provider-registered (provider principal))
  (default-to false (get registered (map-get? healthcare-providers { provider: provider })))
)

;; ;; Fold helper to accumulate permission IDs if they exist for a given user and accessor
;; (define-private (accumulate-permission-if-exists 
;;     (permission-id-to-check uint) 
;;     (accumulator {user: principal, accessor: principal, found-permissions: (list 20 uint)}))
;;   (if (is-some (map-get? data-permissions { 
;;         user: (get user accumulator), 
;;         accessor: (get accessor accumulator), 
;;         permission-id: permission-id-to-check 
;;       }))
;;     ;; ;; If permission exists, append its ID to the list in the accumulator
;;     ;; (let ((list-element-to-append (unwrap! (as-max-len? (list permission-id-to-check) u1) 
;;     ;;                                     (err ERR-INVALID-PARAMETERS)))) ;; Should always succeed
;;     ;;   (merge accumulator { 
;;     ;;     found-permissions: (unwrap-panic (as-max-len? (append (get found-permissions accumulator) list-element-to-append) u20))
;;     ;;   })
;;     ;; )
;;     ;; Otherwise, return the accumulator unchanged
;;     accumulator
;;   )
;; )

;; ;; Helper function to get all permission IDs granted to an accessor
;; (define-private (get-user-permissions (user principal) (accessor principal))
;;   (let (
;;     (potential-ids (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19))
;;     (initial-accumulator {user: user, accessor: accessor, found-permissions: (as-max-len? (list) u20)})
;;     (result-accumulator (fold accumulate-permission-if-exists potential-ids initial-accumulator))
;;   )
;;     (get found-permissions result-accumulator)
;;   )
;; )

;; Fold helper to check if any permission in a list is valid for a given data type
(define-private (check-permission-in-fold 
    (permission-id uint) 
    (accumulator {user: principal, accessor: principal, data-type: (string-utf8 50), is-valid-found: bool}))
  
  (if (get is-valid-found accumulator)
    ;; If a valid permission has already been found, no need to check further
    accumulator 
    (match (map-get? data-permissions { 
        user: (get user accumulator), 
        accessor: (get accessor accumulator), 
        permission-id: permission-id 
      })
      permission-details ;; If permission details are found
        (let (
          (current-time block-height)
          (data-types (get data-types permission-details))
          (revoked (get revoked permission-details))
          (expires-at (get expires-at permission-details))
          (target-data-type (get data-type accumulator))
        )
          ;; Check if permission is valid (not revoked, not expired, and includes data type)
          (if (and 
                (not revoked)
                (or (is-none expires-at) (> (default-to u0 expires-at) current-time))
                (or (is-some (index-of data-types target-data-type)) (is-some (index-of data-types u"all")))
              )
            ;; If valid, update accumulator
            (merge accumulator {is-valid-found: true})
            ;; Otherwise, return accumulator unchanged
            accumulator
          )
        )
      ;; If permission details are not found for this permission-id, return accumulator unchanged
      accumulator 
    )
  )
)

;; Check if a user has granted access to a specific accessor
;; (define-private (has-valid-permission (user principal) (accessor principal) (data-type (string-utf8 50)))
;;   (let (
;;     (permissions-list (get-user-permissions user accessor))
;;     (initial-accumulator {user: user, accessor: accessor, data-type: data-type, is-valid-found: false})
;;   )
;;     ;; Check each permission to see if it's valid and includes the requested data type
;;     (asserts! (not (is-eq permissions-list (list))) (err ERR-PERMISSION-NOT-FOUND))
    
;;     ;; Use fold to iterate through the permission IDs and check validity
;;     (let ((result-accumulator (fold check-permission-in-fold permissions-list initial-accumulator)))
;;       (get is-valid-found result-accumulator)
;;     )
;;   )
;; )

;; Log a data access event
(define-private (log-data-access (user principal) (accessor principal) (data-types (list 20 (string-utf8 50))) (permission-id uint))
  (let (
    (log-id (get-next-log-id))
  )
    (map-set access-logs
      { user: user, log-id: log-id }
      {
        accessor: accessor,
        timestamp: block-height,
        data-types-accessed: data-types,
        permission-id: permission-id
      }
    )
    log-id
  )
)

;; Check if emergency access is enabled
(define-private (check-emergency-access (user principal) (accessor principal))
  (let (
    (user-info (unwrap! (map-get? users { user: user }) false))
    (emergency-contact (get emergency-contact user-info))
    (emergency-enabled (get emergency-access-enabled user-info))
  )
    (and
      emergency-enabled
      (is-some emergency-contact)
      (is-eq (some accessor) emergency-contact)
    )
  )
)

;; Read-only functions

;; Check if a user exists
(define-read-only (user-exists (user principal))
  (is-user-registered user)
)

;; Get user profile information
(define-read-only (get-user-profile (user principal))
  (map-get? users { user: user })
)

;; Get healthcare provider information
(define-read-only (get-provider-info (provider principal))
  (map-get? healthcare-providers { provider: provider })
)

;; Get health data for a specific ID
;; (define-read-only (get-health-data (user principal) (data-id uint) (accessor principal))
;;   (let (
;;     (data (map-get? health-data { user: user, data-id: data-id }))
;;     (data-type (default-to u"" (get data-type data)))
;;   )
;;     (asserts! (is-some data) ERR-DATA-NOT-FOUND)
;;     (asserts! 
;;       (or 
;;         (is-eq user accessor) 
;;         (has-valid-permission user accessor data-type)
;;         (check-emergency-access user accessor)
;;       ) 
;;       ERR-NOT-AUTHORIZED
;;     )
    
;;     data
;;   )
;; )

;; Get all permission IDs for a specific accessor
;; (define-read-only (get-permissions (user principal) (accessor principal))
;;   (get-user-permissions user accessor)
;; )

;; Get specific permission details
(define-read-only (get-permission-details (user principal) (accessor principal) (permission-id uint))
  (map-get? data-permissions { user: user, accessor: accessor, permission-id: permission-id })
)

;; ;; Check if a specific data access request is authorized
;; (define-read-only (is-access-authorized (user principal) (accessor principal) (data-type (string-utf8 50)))
;;   (or 
;;     (is-eq user accessor)
;;     (has-valid-permission user accessor data-type)
;;     (check-emergency-access user accessor)
;;   )
;; )

;; Public functions

;; Register a new user
(define-public (register-user (encrypted-profile-data-url (optional (string-utf8 256))))
  (let (
    (user tx-sender)
  )
    (asserts! (not (is-user-registered user)) ERR-ALREADY-REGISTERED)
    
    (map-set users
      { user: user }
      {
        registered: true,
        emergency-contact: none,
        emergency-access-enabled: false,
        encrypted-profile-data-url: encrypted-profile-data-url
      }
    )
    (ok true)
  )
)

;; Update user profile
(define-public (update-user-profile (encrypted-profile-data-url (optional (string-utf8 256))))
  (let (
    (user tx-sender)
    (user-info (unwrap! (map-get? users { user: user }) ERR-USER-NOT-FOUND))
  )
    (map-set users
      { user: user }
      (merge user-info { encrypted-profile-data-url: encrypted-profile-data-url })
    )
    (ok true)
  )
)

;; Register as a healthcare provider
(define-public (register-provider (provider-name (string-utf8 100)) (provider-type (string-utf8 50)))
  (let (
    (provider tx-sender)
  )
    (asserts! (not (is-provider-registered provider)) ERR-ALREADY-REGISTERED)
    
    (map-set healthcare-providers
      { provider: provider }
      {
        registered: true,
        provider-name: provider-name,
        provider-type: provider-type,
        verification-status: false,
        verification-date: none
      }
    )
    (ok true)
  )
)

;; Verify a healthcare provider (admin only, in production would use a proper DAO or multi-sig)
;; For demonstration purposes this function is simplified
(define-public (verify-provider (provider principal))
  (let (
    (admin tx-sender)
    (provider-info (unwrap! (map-get? healthcare-providers { provider: provider }) ERR-PROVIDER-NOT-REGISTERED))
  )
    ;; In production, this would have a proper admin check mechanism
    ;; For demo purposes this is a simplified version
    (asserts! (is-eq admin (as-contract tx-sender)) ERR-NOT-AUTHORIZED)
    
    (map-set healthcare-providers
      { provider: provider }
      (merge provider-info { 
        verification-status: true,
        verification-date: (some block-height)
      })
    )
    (ok true)
  )
)

;; Add a new health data entry
(define-public (add-health-data 
  (data-type (string-utf8 50)) 
  (encrypted-data (string-utf8 1024))
  (large-data-url (optional (string-utf8 256)))
  (checksum (string-utf8 64))
)
  (let (
    (user tx-sender)
    (data-id (get-next-data-id))
  )
    (asserts! (is-user-registered user) ERR-USER-NOT-FOUND)
    
    (map-set health-data
      { user: user, data-id: data-id }
      {
        data-type: data-type,
        timestamp: block-height,
        encrypted-data: encrypted-data,
        large-data-url: large-data-url,
        checksum: checksum,
        provider: none
      }
    )
    (ok data-id)
  )
)

;; Add health data as a provider (with user permission)
(define-public (add-provider-health-data 
  (user principal) 
  (data-type (string-utf8 50)) 
  (encrypted-data (string-utf8 1024))
  (large-data-url (optional (string-utf8 256)))
  (checksum (string-utf8 64))
)
  (let (
    (provider tx-sender)
    (data-id (get-next-data-id))
  )
    (asserts! (is-user-registered user) ERR-USER-NOT-FOUND)
    (asserts! (is-provider-registered provider) ERR-PROVIDER-NOT-REGISTERED)
    ;; (asserts! (has-valid-permission user provider data-type) ERR-NOT-AUTHORIZED)
    
    (map-set health-data
      { user: user, data-id: data-id }
      {
        data-type: data-type,
        timestamp: block-height,
        encrypted-data: encrypted-data,
        large-data-url: large-data-url,
        checksum: checksum,
        provider: (some provider)
      }
    )
    (ok data-id)
  )
)

;; Grant data access permission to a healthcare provider or application
(define-public (grant-access 
  (accessor principal) 
  (data-types (list 20 (string-utf8 50)))
  (expires-at (optional uint))
)
  (let (
    (user tx-sender)
    (permission-id (get-next-permission-id))
  )
    (asserts! (is-user-registered user) ERR-USER-NOT-FOUND)
    (asserts! (> (len data-types) u0) ERR-INVALID-PARAMETERS)
    
    (map-set data-permissions
      { user: user, accessor: accessor, permission-id: permission-id }
      {
        granted-at: block-height,
        expires-at: expires-at,
        data-types: data-types,
        revoked: false,
        is-emergency-access: false
      }
    )
    (ok permission-id)
  )
)

;; Revoke a specific access permission
(define-public (revoke-access (accessor principal) (permission-id uint))
  (let (
    (user tx-sender)
    (permission (unwrap! (map-get? data-permissions 
      { user: user, accessor: accessor, permission-id: permission-id })
      ERR-PERMISSION-NOT-FOUND))
  )
    (map-set data-permissions
      { user: user, accessor: accessor, permission-id: permission-id }
      (merge permission { revoked: true })
    )
    (ok true)
  )
)

;; Set up emergency contact
(define-public (set-emergency-contact (contact-principal (optional principal)))
  (let (
    (user tx-sender)
    (user-info (unwrap! (map-get? users { user: user }) ERR-USER-NOT-FOUND))
  )
    (map-set users
      { user: user }
      (merge user-info { emergency-contact: contact-principal })
    )
    (ok true)
  )
)

;; Enable or disable emergency access
(define-public (set-emergency-access (enabled bool))
  (let (
    (user tx-sender)
    (user-info (unwrap! (map-get? users { user: user }) ERR-USER-NOT-FOUND))
  )
    (map-set users
      { user: user }
      (merge user-info { emergency-access-enabled: enabled })
    )
    (ok true)
  )
)

;; Access data in emergency (only for emergency contact)
(define-public (emergency-access (user principal) (data-id uint))
  (let (
    (accessor tx-sender)
    (user-info (unwrap! (map-get? users { user: user }) ERR-USER-NOT-FOUND))
    (emergency-contact (get emergency-contact user-info))
    (emergency-enabled (get emergency-access-enabled user-info))
  )
    ;; Check if emergency access is enabled and the accessor is the emergency contact
    (asserts! emergency-enabled ERR-EMERGENCY-ACCESS-NOT-ENABLED)
    (asserts! (is-eq (some accessor) emergency-contact) ERR-NOT-AUTHORIZED)
    
    ;; Get the data
    (let (
      (data (unwrap! (map-get? health-data { user: user, data-id: data-id }) ERR-DATA-NOT-FOUND))
      (data-type (get data-type data))
    )
      ;; Log the emergency access
      (log-data-access user accessor (list data-type) u0)
      
      (ok data)
    )
  )
)