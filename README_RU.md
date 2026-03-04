[🇬🇧 English](README.md) | [🇷🇺 Русский](README_RU.md)

# EWSP Core Library

<p align="center">
  <strong>Единственная реализация криптографии для WakeLink Protocol</strong>
</p>

<p align="center">
  <a href="https://github.com/wakelinkdev/ewsp-core/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Версия"></a>
  <a href="https://github.com/wakelinkdev/ewsp-core/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Сборка"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-NGC%20v1.0-orange.svg" alt="Лицензия"></a>
  <a href="https://github.com/wakelinkdev"><img src="https://img.shields.io/badge/org-wakelinkdev-purple.svg" alt="Организация"></a>
</p>

<p align="center">
  <a href="https://github.com/wakelinkdev/ewsp-core">ewsp-core</a> •
  <a href="https://github.com/wakelinkdev/firmware">firmware</a> •
  <a href="https://github.com/wakelinkdev/cli">cli</a> •
  <a href="https://github.com/wakelinkdev/android">android</a> •
  <a href="https://github.com/wakelinkdev/multiplatform">multiplatform</a>
</p>

---

## 📋 Обзор

EWSP Core Library — **ЕДИНСТВЕННАЯ** реализация криптографических примитивов для всего проекта WakeLink. Все остальные компоненты (firmware, Python client, Android, KMP) используют эту библиотеку через интерфейсы/биндинги.

### Архитектура

```
ewsp-core/                 ← ЕДИНСТВЕННАЯ реализация криптографии
├── src/ewsp_crypto.c      ← SHA256, HMAC, HKDF, ChaCha20, XChaCha20
├── include/ewsp_crypto.h  ← C API
└── bindings/
    └── python/            ← ctypes binding для Python
    
firmware/         
└── ewsp_core.h            ← C++ wrapper (inline, вызывает ewsp-core)

cli/           
└── core/crypto/
    ├── native_binding.py  ← ctypes binding к ewsp-core
    └── wakelink_crypto.py ← Pure Python FALLBACK (если нет .so/.dll)

android/          
└── WakeLinkCrypto.kt      ← Kotlin FALLBACK (TODO: JNI binding)

multiplatform/    
└── WakeLinkCrypto.kt      ← KMP FALLBACK (TODO: cinterop binding)
```

### Принципы

1. **Single Source of Truth** — вся криптология реализована ТОЛЬКО в ewsp-core
2. **No Duplication** — платформы используют биндинги, не копируют код
3. **Fallback Pattern** — если native недоступен, используется чистая реализация
4. **Security First** — все исправления безопасности применяются в одном месте

---

## 🔐 Криптографические примитивы

| Примитив | Функция | Описание |
|----------|---------|----------|
| SHA-256 | `ewsp_sha256()` | FIPS 180-4 хеширование |
| HMAC-SHA256 | `ewsp_hmac_sha256()` | RFC 2104 аутентификация |
| HKDF-SHA256 | `ewsp_hkdf()` | RFC 5869 деривация ключей |
| ChaCha20 | `ewsp_chacha20()` | RFC 7539 шифрование |
| XChaCha20 | `ewsp_xchacha20()` | Расширенный nonce (24 байта) |

### Исправления безопасности (v3.0)

- **CRYPTO-01**: Удалён небезопасный `rand()` fallback для RNG
- **CRYPTO-02**: Только аппаратный RNG (esp_fill_random)
- **CRYPTO-03**: Разделение ключей через HKDF (отдельные ключи для шифрования и аутентификации)
- **CRYPTO-04/05**: Сравнение за константное время против timing attacks

---

## 🚀 Быстрый старт

### Сборка библиотеки

```bash
cd ewsp-core
mkdir build && cd build
cmake .. -DEWSP_BUILD_TESTS=ON
cmake --build .
ctest -V
```

### Использование в C/C++

```c
#include <ewsp_crypto.h>

// Хеширование
uint8_t hash[32];
ewsp_sha256(data, len, hash);

// HKDF деривация ключей  
uint8_t enc_key[32], auth_key[32];
ewsp_hkdf(NULL, 0, master_key, 32, "wakelink_encryption_v2", 22, enc_key, 32);
ewsp_hkdf(NULL, 0, master_key, 32, "wakelink_authentication_v2", 26, auth_key, 32);

// XChaCha20 шифрование
uint8_t nonce[24];
// ... fill nonce with hardware RNG
ewsp_xchacha20(key, nonce, 0, plaintext, ciphertext, len);

// Constant-time comparison
if (ewsp_constant_time_compare(mac1, mac2, 32)) {
    // MACs match
}
```

### Использование в Python

```python
from ewsp_core.bindings.python import ewsp_core

# Через ctypes binding (предпочтительно)
lib = ewsp_core.get_lib()
# ... или через CryptoManager
from wakelink_client.core.crypto import get_crypto
crypto = get_crypto(token)  # автовыбор native/pure

# Полный контроль
pm = PacketManager("my_token_32chars_minimum", "WL12345678")
packet = pm.create_command("wake", {"mac": "AA:BB:CC:DD:EE:FF"})
print(packet)

# Сохранение состояния цепочки
state = pm.export_state()
print(f"TX seq: {state.tx_sequence}, RX seq: {state.rx_sequence}")
```

---

## 📁 Структура проекта

```
ewsp-core/
├── include/                    # Заголовочные файлы
│   ├── ewsp.h                  # Главный заголовок
│   ├── ewsp_types.h           # Базовые типы
│   ├── ewsp_errors.h          # Коды ошибок
│   ├── ewsp_crypto.h          # Криптография
│   ├── ewsp_models.h          # Структуры данных
│   ├── ewsp_chain.h           # Состояние blockchain chain
│   ├── ewsp_packet.h          # Менеджер пакетов
│   ├── ewsp_commands.h        # Команды и билдеры
│   └── ewsp_json.h            # Минимальный JSON
│
├── src/                       # Реализация
│   ├── ewsp.c                 # Главный модуль
│   ├── ewsp_crypto.c          # SHA256, HMAC, HKDF, ChaCha20, XChaCha20
│   ├── ewsp_errors.c          # Таблица ошибок
│   ├── ewsp_chain.c           # Управление цепочкой
│   ├── ewsp_packet.c          # Создание/обработка пакетов
│   ├── ewsp_commands.c        # Билдеры команд
│   ├── ewsp_models.c          # Инициализация структур
│   └── ewsp_json.c            # JSON парсер/райтер
│
├── bindings/                  # Биндинги для платформ
│   └── python/
│       ├── __init__.py
│       ├── ewsp_core.py       # ctypes биндинги
│       └── crypto_pure.py     # Fallback на чистом Python
│
├── tests/                     # Тесты
│   ├── test_main.c
│   ├── test_crypto.c
│   ├── test_json.c
│   ├── test_chain.c
│   └── test_packet.c
│
├── CMakeLists.txt             # CMake конфигурация
└── README.md                  # Этот файл
```

---

## 🔐 Криптография

### Алгоритмы

| Алгоритм | Использование | Реализация |
|----------|---------------|------------|
| SHA-256 | Хэширование, деривация ключей | Встроенная |
| HMAC-SHA256 | Аутентификация пакетов | Встроенная |
| HKDF-SHA256 | Расширение ключей | Встроенная |
| ChaCha20 | Шифрование (12Б nonce) | Встроенная |
| XChaCha20 | Шифрование (24Б nonce) | Встроенная |

### Деривация ключей

```
device_token (≥32 символов)
        │
        ▼
    SHA-256
        │
        ▼
┌───────────────────┐
│   32-байтовый ключ│
├───────────────────┤
│  chacha_key (32)  │ → XChaCha20 шифрование
│   hmac_key (32)   │ → HMAC-SHA256 подпись
└───────────────────┘
```

### Формат payload

```
┌────────────┬──────────────────────┬────────────────┐
│ 2Б length  │ XChaCha20 ciphertext │ 24Б nonce      │
│ (big-end)  │ (переменная длина)   │                │
└────────────┴──────────────────────┴────────────────┘
```

---

## 📦 Формат пакета (Protocol v1.0)

### Внешний JSON

```json
{
  "v": "1.0",
  "id": "WL12345678",
  "seq": 42,
  "prev": "0123456789abcdef...",
  "p": "<hex_encrypted_payload>",
  "sig": "<hmac_sha256_hex>"
}
```

### Внутренний JSON (зашифрованный)

```json
{
  "cmd": "wake",
  "d": {"mac": "AA:BB:CC:DD:EE:FF"},
  "rid": "ABC12345"
}
```

### Blockchain Chain

Каждый пакет содержит:
- `seq` — монотонно возрастающий номер
- `prev` — SHA256 хэш предыдущего пакета

Это обеспечивает:
- ✅ Защиту от replay-атак
- ✅ Обнаружение потери пакетов
- ✅ Гарантию порядка

---

## 🔧 Справочник API

### Основные функции

```c
// Инициализация/очистка библиотеки
ewsp_error_t ewsp_init(void);
void ewsp_cleanup(void);

// Версии
const char* ewsp_version(void);        // "1.0.0"
const char* ewsp_protocol_version(void); // "1.0"
```

### Менеджер пакетов

```c
// Создание контекста
ewsp_error_t ewsp_packet_init(ewsp_packet_ctx* ctx, 
                               const char* token,
                               const char* device_id);
void ewsp_packet_cleanup(ewsp_packet_ctx* ctx);

// Создание пакетов
ewsp_error_t ewsp_packet_create_command(ewsp_packet_ctx* ctx,
                                         const char* command,
                                         const char* data_json,
                                         char* packet_out,
                                         size_t packet_out_size);

// Обработка входящих пакетов
ewsp_error_t ewsp_packet_process(ewsp_packet_ctx* ctx,
                                  const char* packet_json,
                                  ewsp_packet_result_t* result);

// Сохранение/загрузка состояния
void ewsp_packet_export_state(const ewsp_packet_ctx* ctx, 
                               ewsp_chain_snapshot_t* snapshot);
void ewsp_packet_import_state(ewsp_packet_ctx* ctx,
                               const ewsp_chain_snapshot_t* snapshot);
```

### Криптография

```c
// Контекст
ewsp_error_t ewsp_crypto_init(ewsp_crypto_ctx* ctx,
                               const char* token,
                               size_t token_len);
void ewsp_crypto_cleanup(ewsp_crypto_ctx* ctx);

// Шифрование
ewsp_error_t ewsp_crypto_encrypt(const ewsp_crypto_ctx* ctx,
                                  const uint8_t* plaintext,
                                  size_t plaintext_len,
                                  char* hex_out,
                                  size_t hex_out_size);

ewsp_error_t ewsp_crypto_decrypt(const ewsp_crypto_ctx* ctx,
                                  const char* hex_payload,
                                  uint8_t* plaintext_out,
                                  size_t plaintext_out_size,
                                  size_t* plaintext_len_out);

// Подпись
void ewsp_crypto_sign(const ewsp_crypto_ctx* ctx,
                       const uint8_t* data,
                       size_t data_len,
                       char* signature_hex_out);

bool ewsp_crypto_verify(const ewsp_crypto_ctx* ctx,
                         const uint8_t* data,
                         size_t data_len,
                         const char* signature_hex);
```

### Низкоуровневая криптография

```c
// SHA-256
void ewsp_sha256(const uint8_t* data, size_t len, ewsp_hash_t hash_out);

// HMAC-SHA256
void ewsp_hmac_sha256(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       ewsp_hash_t mac_out);

// HKDF-SHA256
void ewsp_hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                       const uint8_t* salt, size_t salt_len,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len);

// XChaCha20
void ewsp_xchacha20(const uint8_t* key,
                     const uint8_t* nonce,
                     const uint8_t* input,
                     uint8_t* output,
                     size_t len);

// Случайные байты
void ewsp_random_bytes(uint8_t* buffer, size_t len);
```

---

## 🧪 Тестирование

```bash
# Все тесты
./build/ewsp_tests

# Только криптография
./build/ewsp_tests crypto

# Только пакеты
./build/ewsp_tests packet

# Только JSON
./build/ewsp_tests json

# Только chain
./build/ewsp_tests chain
```

---

## 🔗 Интеграция с платформами

### Прошивка (ESP8266/ESP32)

```cpp
// Добавить в platformio.ini:
// lib_deps = file://path/to/ewsp-core

#include <ewsp.h>

ewsp_packet_ctx ctx;
ewsp_packet_init(&ctx, config.token, config.device_id);

// Обработка входящего пакета
ewsp_packet_result_t result;
if (ewsp_packet_process(&ctx, incoming_json, &result) == EWSP_OK) {
    handle_command(result.command, result.data_json);
}
```

### Python клиент

```python
# Установка
pip install -e ewsp/bindings/python

# Использование
from ewsp_core import PacketManager

pm = PacketManager(device.token, device.device_id)
packet = pm.create_command("wake", {"mac": target_mac})
response = send_tcp(device.ip, 99, packet)
```

### Android (JNI)

```kotlin
// Загрузка библиотеки
System.loadLibrary("ewsp_core")

// Использование через JNI wrapper
val pm = EwspPacketManager(token, deviceId)
val packet = pm.createCommand("ping")
```

### Kotlin Multiplatform

```kotlin
// expect/actual с нативной реализацией для каждой платформы
expect class EwspCore {
    fun createPacket(cmd: String, data: Map<String, Any>?): String
    fun processPacket(json: String): PacketResult
}
```

---

## 📊 Сравнение производительности

| Операция | Pure Python | EWSP Core (C) | Ускорение |
|----------|-------------|---------------|-----------|
| SHA-256 | 45 µs | 2 µs | 22x |
| Шифрование 1КБ | 890 µs | 35 µs | 25x |
| Создание пакета | 1.2 ms | 50 µs | 24x |
| Обработка пакета | 1.5 ms | 60 µs | 25x |

---

## 📜 Лицензия

NGC License v1.0 — только для личного использования.

Коммерческое использование требует письменного разрешения.

---

## 🤝 Связь

- **Issues:** GitHub Issues
- **Автор:** deadboizxc
