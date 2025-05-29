# LoopPulse Health Monitor

A decentralized health monitoring platform built on Stacks blockchain that enables secure management and sharing of personal health data.

## Overview

LoopPulse allows users to securely store and manage their health metrics while maintaining complete ownership of their data. The platform facilitates:

- Secure storage of various health metrics (heart rate, blood pressure, glucose levels, etc.)
- Selective data sharing with healthcare providers and applications
- Emergency access mechanisms for authorized contacts
- Immutable audit trail of all data access
- Privacy-preserving data management through encryption

## Architecture

The LoopPulse platform is built around a core smart contract that manages data storage, access controls, and permissions.

```mermaid
graph TD
    A[User] -->|Register/Store Data| B[LoopPulse Core Contract]
    C[Healthcare Provider] -->|Request Access| B
    B -->|Grant/Revoke Access| D[Data Permissions]
    B -->|Store| E[Health Data]
    B -->|Log Access| F[Access Logs]
    G[Emergency Contact] -->|Emergency Access| B
```

### Key Components
- **Users**: Register and manage their health data and access permissions
- **Healthcare Providers**: Can request access and add medical data with permission
- **Data Permissions**: Granular access control with expiration dates
- **Access Logs**: Immutable record of all data access events
- **Emergency Access**: Controlled access for designated emergency contacts

## Contract Documentation

### LoopPulse Core Contract

The main contract (`looppulse-core.clar`) manages all platform functionality:

#### Data Structures
- `users`: User profiles and emergency contact settings
- `healthcare-providers`: Registered and verified healthcare providers
- `health-data`: Encrypted health records
- `data-permissions`: Access control permissions
- `access-logs`: Audit trail of data access

#### Key Functions

##### User Management
```clarity
(define-public (register-user (encrypted-profile-data-url (optional (string-utf8 256))))
(define-public (update-user-profile (encrypted-profile-data-url (optional (string-utf8 256))))
```

##### Healthcare Provider Management
```clarity
(define-public (register-provider (provider-name (string-utf8 100)) (provider-type (string-utf8 50)))
(define-public (verify-provider (provider principal))
```

##### Data Management
```clarity
(define-public (add-health-data (data-type (string-utf8 50)) (encrypted-data (string-utf8 1024)) (large-data-url (optional (string-utf8 256))) (checksum (string-utf8 64)))
(define-public (add-provider-health-data (user principal) (data-type (string-utf8 50)) (encrypted-data (string-utf8 1024)) (large-data-url (optional (string-utf8 256))) (checksum (string-utf8 64)))
```

##### Access Control
```clarity
(define-public (grant-access (accessor principal) (data-types (list 20 (string-utf8 50))) (expires-at (optional uint)))
(define-public (revoke-access (accessor principal) (permission-id uint))
```

## Getting Started

### Prerequisites
- Clarinet
- Stacks wallet
- Node.js environment

### Installation

1. Clone the repository
2. Install dependencies with Clarinet
```bash
clarinet integrate
```

### Usage Examples

1. Register as a user:
```clarity
(contract-call? .looppulse-core register-user (some "https://example.com/profile"))
```

2. Add health data:
```clarity
(contract-call? .looppulse-core add-health-data "heart-rate" "encrypted_data_here" none "checksum_here")
```

3. Grant access to a provider:
```clarity
(contract-call? .looppulse-core grant-access 'PROVIDER_ADDRESS (list "heart-rate" "blood-pressure") (some u100))
```

## Security Considerations

1. Data Encryption
   - All health data must be encrypted before storage
   - Only encrypted data URLs should be stored on-chain

2. Access Control
   - Regular audit of access permissions
   - Immediate revocation of compromised permissions
   - Time-limited access grants

3. Emergency Access
   - Carefully manage emergency contact settings
   - Regular verification of emergency access configuration

4. Provider Verification
   - Healthcare providers must be verified before accessing data
   - Regular review of provider credentials

## Development

### Testing

Run the test suite:
```bash
clarinet test
```

### Local Development

1. Start local Clarinet console:
```bash
clarinet console
```

2. Deploy contracts:
```bash
clarinet deploy
```

### Key Considerations

- Always verify transaction signatures
- Implement proper error handling
- Monitor gas costs for large operations
- Regular security audits
- Keep encrypted data backups off-chain