# EWSP-Core Fuzzing

AFL++ fuzzing harnesses for security testing of ewsp-core library.

## Prerequisites

### Install AFL++

```bash
# Ubuntu/Debian
sudo apt-get install afl++

# macOS
brew install aflplusplus

# From source
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
```

## Build Harnesses

### Build with AFL compiler

```bash
cd ewsp-core

# Build library with AFL instrumentation
mkdir build-fuzz && cd build-fuzz
CC=afl-gcc CXX=afl-g++ cmake .. -DEWSP_BUILD_TESTS=OFF
make

# Build harnesses
cd ../fuzz
afl-gcc -o fuzz_crypto fuzz_crypto.c -I../include -L../build-fuzz -lewsp_core
afl-gcc -o fuzz_json fuzz_json.c -I../include -L../build-fuzz -lewsp_core
afl-gcc -o fuzz_packet fuzz_packet.c -I../include -L../build-fuzz -lewsp_core
```

### Build with AddressSanitizer (recommended)

```bash
AFL_USE_ASAN=1 afl-gcc -o fuzz_crypto fuzz_crypto.c -I../include -L../build-fuzz -lewsp_core -fsanitize=address
AFL_USE_ASAN=1 afl-gcc -o fuzz_json fuzz_json.c -I../include -L../build-fuzz -lewsp_core -fsanitize=address
AFL_USE_ASAN=1 afl-gcc -o fuzz_packet fuzz_packet.c -I../include -L../build-fuzz -lewsp_core -fsanitize=address
```

## Run Fuzzing

### Setup directories

```bash
mkdir -p corpus/crypto corpus/json corpus/packet
mkdir -p output/crypto output/json output/packet
```

### Create seed inputs

```bash
# Crypto seeds
echo -n "test data for hashing" > corpus/crypto/seed1
head -c 64 /dev/urandom > corpus/crypto/seed2
echo -n "0102030405060708090a0b0c0d0e0f10" > corpus/crypto/hex_seed

# JSON seeds
echo '{"cmd":"ping","rid":"test123"}' > corpus/json/seed1
echo '{"v":"1.0","id":"WL12345678","seq":1,"prev":"0000000000000000000000000000000000000000000000000000000000000000","p":"{}","sig":"abc"}' > corpus/json/seed2
echo '{"status":"ok","rid":"req1","data":{"key":"value"}}' > corpus/json/seed3

# Packet seeds (same as JSON for protocol packets)
cp corpus/json/seed2 corpus/packet/seed1
```

### Run AFL++

```bash
# Crypto fuzzing (parallel)
afl-fuzz -i corpus/crypto -o output/crypto -M main -- ./fuzz_crypto
# In another terminal:
afl-fuzz -i corpus/crypto -o output/crypto -S worker1 -- ./fuzz_crypto

# JSON fuzzing
afl-fuzz -i corpus/json -o output/json -- ./fuzz_json

# Packet fuzzing
afl-fuzz -i corpus/packet -o output/packet -- ./fuzz_packet
```

### With timeout

```bash
# Run for 24 hours
timeout 86400 afl-fuzz -i corpus/crypto -o output/crypto -- ./fuzz_crypto
```

## Analyze Results

### Check crash status

```bash
ls output/crypto/default/crashes/
ls output/json/default/crashes/
ls output/packet/default/crashes/
```

### Replay crashes

```bash
./fuzz_crypto < output/crypto/default/crashes/id:000000*
```

### Generate coverage report

```bash
# Build with coverage
gcc -fprofile-arcs -ftest-coverage -o fuzz_crypto fuzz_crypto.c -I../include -L../build -lewsp_core

# Run with corpus
for f in output/crypto/default/queue/*; do ./fuzz_crypto < "$f"; done

# Generate report
gcov fuzz_crypto.c
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
```

## Fuzzing Targets

| Harness | Target Functions | Risk Areas |
|---------|------------------|------------|
| fuzz_crypto | SHA256, HMAC, HKDF, XChaCha20 | Buffer overflows, key handling |
| fuzz_json | JSON parse/build | Injection, DoS, memory corruption |
| fuzz_packet | Packet serialize/verify | Protocol violations, chain attacks |

## Continuous Fuzzing

### Docker setup

```dockerfile
FROM aflplusplus/aflplusplus:latest

COPY . /ewsp-core
WORKDIR /ewsp-core

RUN mkdir build && cd build && \
    CC=afl-clang-fast cmake .. && \
    make

RUN cd fuzz && \
    afl-clang-fast -o fuzz_crypto fuzz_crypto.c -I../include -L../build -lewsp_core && \
    afl-clang-fast -o fuzz_json fuzz_json.c -I../include -L../build -lewsp_core && \
    afl-clang-fast -o fuzz_packet fuzz_packet.c -I../include -L../build -lewsp_core

CMD ["afl-fuzz", "-i", "corpus/crypto", "-o", "output/crypto", "--", "./fuzz_crypto"]
```

### GitHub Actions integration

```yaml
name: Fuzzing
on:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install AFL++
        run: sudo apt-get install -y afl++
        
      - name: Build harnesses
        run: |
          cd ewsp-core
          mkdir build && cd build
          CC=afl-gcc cmake ..
          make
          cd ../fuzz
          afl-gcc -o fuzz_crypto fuzz_crypto.c -I../include -L../build -lewsp_core
          
      - name: Run fuzzing (1 hour)
        run: |
          cd ewsp-core/fuzz
          mkdir -p corpus/crypto output/crypto
          echo "test" > corpus/crypto/seed
          timeout 3600 afl-fuzz -i corpus/crypto -o output/crypto -- ./fuzz_crypto || true
          
      - name: Upload crashes
        uses: actions/upload-artifact@v3
        with:
          name: fuzzing-crashes
          path: ewsp-core/fuzz/output/*/crashes/
```

## Expected Findings

The fuzzing should NOT find:
- Buffer overflows (bounds checking in place)
- Use-after-free (proper memory management)  
- Stack corruption (input validation)
- Integer overflows (checked arithmetic)

If any crashes are found, please report to security@wakelink.example.com.

## Resources

- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus)
- [Fuzzing Best Practices](https://google.github.io/clusterfuzz/reference/coverage-guided/)
- [OWASP Fuzzing Guide](https://owasp.org/www-community/Fuzzing)
