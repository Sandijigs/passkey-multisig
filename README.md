# 🔐 Passkey-Protected Multisig

A secure multisig wallet where each signer authenticates using biometrics/passkeys (Face ID, Touch ID), built with **Clarity 4** and **Epoch 3.3**.

## ✅ Project Status

- ✅ **Clarity 4 compatible** (Epoch 3.3)
- ✅ **All tests passing** (13 comprehensive test cases)
- ✅ **Event logging** for monitoring and audit trails
- ✅ **Best practices .gitignore**
- ✅ **Syntax validated** with Clarinet 3.11.0
- ✅ **Ready for testnet deployment**
- ✅ **Comprehensive documentation**

## 🎯 Clarity 4 Features Used

| Feature | Usage | Line Reference |
|---------|-------|----------------|
| `secp256r1-verify` | Verify passkey signatures from each signer | [291](contracts/passkey-multisig.clar#L291), [357](contracts/passkey-multisig.clar#L357) |
| `stacks-block-time` | Time-bound transaction approvals and event timestamps | [210](contracts/passkey-multisig.clar#L210), [285](contracts/passkey-multisig.clar#L285) |
| `to-ascii?` | Human-readable transaction descriptions | [195-211](contracts/passkey-multisig.clar#L195-L211) |
| `print` | Event logging for monitoring | [96-149](contracts/passkey-multisig.clar#L96-L149) |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Passkey Multisig Wallet                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                    │
│   │ Signer1 │  │ Signer2 │  │ Signer3 │  (Passkey Auth)    │
│   │ 🔑 Face │  │ 🔑 Touch│  │ 🔑 Face │                    │
│   └────┬────┘  └────┬────┘  └────┬────┘                    │
│        │            │            │                          │
│        └────────────┼────────────┘                          │
│                     ▼                                       │
│   ┌─────────────────────────────────────────────────────┐   │
│   │           secp256r1-verify (WebAuthn)               │   │
│   └─────────────────────────────────────────────────────┘   │
│                     │                                       │
│                     ▼                                       │
│   ┌─────────────────────────────────────────────────────┐   │
│   │      Threshold Check (e.g., 2-of-3 required)        │   │
│   └─────────────────────────────────────────────────────┘   │
│                     │                                       │
│                     ▼                                       │
│   ┌─────────────────────────────────────────────────────┐   │
│   │            Execute Transaction                       │   │
│   │         (if threshold met & not expired)            │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- **Clarinet 3.11.0+** (Clarity 4 support)
- **Deno** (for running tests)
- **Node.js 16+** (optional, for development tools)

### Installation & Testing

```bash
# Navigate to project directory
cd passkey-multisig

# Verify Clarity 4 syntax (Epoch 3.3)
clarinet check

# Run comprehensive test suite (13 test cases)
clarinet test

# Start interactive REPL console
clarinet console
```

### Deployment

```bash
# Generate deployment plan for simnet
clarinet deployments generate --simnet

# Generate deployment plan for testnet
clarinet deployments generate --testnet

# Start local devnet for testing
clarinet integrate

# Apply deployment to testnet (after configuration)
clarinet deployments apply --testnet
```

### Console Examples

```clarity
;; Create a 2-of-3 multisig
(contract-call? .passkey-multisig create-multisig
  0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  "Family Wallet"
  u2
  (list 0x03pubkey1... 0x03pubkey2... 0x03pubkey3...))

;; Deposit funds
(contract-call? .passkey-multisig deposit
  0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  u1000000000)

;; Get multisig info
(contract-call? .passkey-multisig get-multisig
  0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
```

## 📋 Contract Functions

### Setup Functions
| Function | Description |
|----------|-------------|
| `create-multisig` | Create new multisig with signers |
| `deposit` | Add funds to multisig |

### Transaction Functions
| Function | Description |
|----------|-------------|
| `propose-tx` | Propose a new transaction |
| `approve-tx` | Sign/approve pending transaction |
| `execute-tx` | Execute once threshold met |

### Read-Only Functions
| Function | Description |
|----------|-------------|
| `get-multisig` | Get multisig details |
| `get-signer` | Get signer info by index |
| `get-pending-tx` | Get transaction details |
| `has-signed` | Check if signer approved |
| `is-tx-valid` | Check if tx is still valid |
| `generate-tx-summary` | Human-readable summary |

## 💡 Key Features

1. **🔐 Biometric Auth**: Each signer uses Face ID/Touch ID via WebAuthn passkeys
2. **⚙️ Flexible Threshold**: M-of-N configuration (e.g., 2-of-3, 3-of-5)
3. **⏰ Time-Bound Approvals**: Transactions expire after 7 days (604,800 seconds)
4. **📊 Event Logging**: Complete audit trail with `print` statements for all key operations
5. **📝 Human-Readable Descriptions**: Using `to-ascii?` for transaction summaries
6. **🛡️ Security-First Design**: Multiple validation layers and anti-replay protection

## 🔒 Security Features

- ✅ **Passkey Verification**: All signatures verified with `secp256r1-verify` (WebAuthn compatible)
- ✅ **Time-Locked Approvals**: Prevents execution of stale transactions using `stacks-block-time`
- ✅ **Anti-Replay Protection**: Nonce tracking and unique transaction IDs
- ✅ **Threshold Enforcement**: On-chain validation of M-of-N signatures
- ✅ **Input Validation**: Comprehensive checks on all user inputs
- ✅ **Active Signer Management**: Only active signers can participate

## 📊 Event Monitoring

The contract emits detailed events for monitoring and analytics:

```clarity
;; Events emitted:
- multisig-created: When a new multisig wallet is created
- deposit: When funds are deposited to the wallet
- tx-proposed: When a new transaction is proposed
- tx-approved: When a signer approves a transaction
- tx-executed: When a transaction is executed
```

All events include timestamps using `stacks-block-time` for accurate audit trails.

## 🧪 Test Coverage

13 comprehensive test cases covering:
- ✅ Multisig creation with various configurations
- ✅ Signer validation and management
- ✅ Deposit functionality
- ✅ Transaction proposal and approval workflow
- ✅ Invalid threshold handling
- ✅ Edge cases and error conditions
- ✅ Read-only function verification

## 🚀 Deployment Guide

### Testnet Deployment

1. **Configure settings**:
   ```bash
   # Edit settings/Testnet.toml with your mnemonic
   # Ensure you have testnet STX for deployment
   ```

2. **Generate deployment plan**:
   ```bash
   clarinet deployments generate --testnet
   ```

3. **Deploy contract**:
   ```bash
   clarinet deployments apply --testnet
   ```

4. **Verify deployment**:
   - Check contract on [Stacks Explorer](https://explorer.hiro.so/?chain=testnet)
   - Test contract functions via API or console

### Mainnet Deployment (Production)

⚠️ **Important**: Thoroughly test on testnet before mainnet deployment!

1. Configure mainnet settings
2. Audit contract code
3. Generate deployment plan
4. Apply deployment with caution

## 🏆 Clarity 4 & Epoch 3.3 Compliance

This contract demonstrates best practices for Clarity 4 development:

- ✅ **Epoch 3.3**: Configured in [Clarinet.toml](Clarinet.toml#L12)
- ✅ **secp256r1-verify**: WebAuthn passkey signature verification
- ✅ **stacks-block-time**: Time-based transaction expiration
- ✅ **to-ascii?**: Human-readable transaction summaries
- ✅ **print**: Comprehensive event logging for monitoring
- ✅ **No circular dependencies**: Optimized function structure
- ✅ **Production-ready**: Syntax validated and tests passing

## 📚 Additional Resources

- [Clarity Language Reference](https://docs.stacks.co/clarity/)
- [WebAuthn/Passkeys Overview](https://webauthn.io/)
- [Clarinet Documentation](https://github.com/hirosystems/clarinet)
- [Stacks Blockchain](https://www.stacks.co/)

## 📜 License

MIT License
