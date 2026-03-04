# Changelog

All notable changes to EWSP Core Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-08

### Added
- **Blockchain Packet Chaining**: SHA-256 linked packets for replay protection without timestamps
- **XChaCha20 Encryption**: Extended nonce (24 bytes) stream cipher with key separation
- **HKDF Key Derivation**: RFC 5869 compliant key derivation with domain separation
- **HMAC-SHA256 Authentication**: Message authentication with constant-time verification
- **Cross-Platform RNG**: Platform-specific secure random:
  - Windows: CryptGenRandom
  - Linux/macOS: /dev/urandom
  - ESP32/ESP8266: esp_random() hardware RNG
- **Protocol v1.0**: Complete packet format with encryption, signing, and chain management
- **JSON Serialization**: Built-in JSON parser/builder for packet handling
- **Command System**: Extensible command dispatch with type-safe serialization
- **Error Handling**: Comprehensive error codes with descriptive messages

### Security
- **CRYPTO-03**: Key separation via HKDF (encryption key ≠ authentication key)
- **CRYPTO-04**: Constant-time comparison for all MAC/hash verification
- **Secure Memory**: `ewsp_secure_zero()` for sensitive data cleanup
- **No Unsafe Fallbacks**: Compilation error instead of rand() fallback

### API
- All public symbols use `ewsp_` prefix
- Full Doxygen documentation for public API
- Clean separation: `ewsp_types.h`, `ewsp_errors.h`, `ewsp_crypto.h`, `ewsp_packet.h`

## [1.0.0] - 2025-06-15

### Added
- Initial release
- SHA-256 hash implementation
- HMAC-SHA256 authentication
- ChaCha20 stream cipher
- Basic packet serialization

---

## Roadmap

### [2.1.0] - Planned
- **XChaCha20-Poly1305 AEAD**: Authenticated encryption with associated data
- **Session Management**: X25519 key exchange, forward secrecy, session binding
- **Python Bindings**: ctypes wrapper for Python clients
- **Kotlin/JNI Bindings**: Android native support

### [3.0.0] - Future
- Ed25519 signatures for firmware updates
- WASM build for browser clients
- Formal security audit
