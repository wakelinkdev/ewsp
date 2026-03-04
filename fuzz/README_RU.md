[🇬🇧 English](README.md) | [🇷🇺 Русский](README_RU.md)

# EWSP-Core Fuzzing

Тест-жгуты AFL++ для тестирования безопасности библиотеки ewsp-core.

## Предварительные требования

### Установка AFL++

```bash
# Ubuntu/Debian
sudo apt-get install afl++

# macOS
brew install aflplusplus

# Из исходников
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
```

## Сборка тест-жгутов

### Сборка с компилятором AFL

```bash
cd ewsp-core

# Сборка библиотеки с инструментацией AFL
mkdir build-fuzz && cd build-fuzz
CC=afl-gcc CXX=afl-g++ cmake .. -DEWSP_BUILD_TESTS=OFF
make

# Сборка тест-жгутов
cd ../fuzz
afl-gcc -o fuzz_crypto fuzz_crypto.c -I../include -L../build-fuzz -lewsp_core
afl-gcc -o fuzz_json fuzz_json.c -I../include -L../build-fuzz -lewsp_core
afl-gcc -o fuzz_packet fuzz_packet.c -I../include -L../build-fuzz -lewsp_core
```

### Сборка с AddressSanitizer (рекомендуется)

```bash
AFL_USE_ASAN=1 afl-gcc -o fuzz_crypto fuzz_crypto.c -I../include -L../build-fuzz -lewsp_core -fsanitize=address
AFL_USE_ASAN=1 afl-gcc -o fuzz_json fuzz_json.c -I../include -L../build-fuzz -lewsp_core -fsanitize=address
AFL_USE_ASAN=1 afl-gcc -o fuzz_packet fuzz_packet.c -I../include -L../build-fuzz -lewsp_core -fsanitize=address
```

## Запуск фаззинга

### Подготовка директорий

```bash
mkdir -p corpus/crypto corpus/json corpus/packet
mkdir -p output/crypto output/json output/packet
```

### Создание начальных входных данных

```bash
# Семена для криптографии
echo -n "test data for hashing" > corpus/crypto/seed1
head -c 64 /dev/urandom > corpus/crypto/seed2
echo -n "0102030405060708090a0b0c0d0e0f10" > corpus/crypto/hex_seed

# Семена для JSON
echo '{"cmd":"ping","rid":"test123"}' > corpus/json/seed1
echo '{"v":"1.0","id":"WL12345678","seq":1,"prev":"0000000000000000000000000000000000000000000000000000000000000000","p":"{}","sig":"abc"}' > corpus/json/seed2
echo '{"status":"ok","rid":"req1","data":{"key":"value"}}' > corpus/json/seed3

# Семена для пакетов (те же, что и JSON для протокольных пакетов)
cp corpus/json/seed2 corpus/packet/seed1
```

### Запуск AFL++

```bash
# Фаззинг криптографии (параллельно)
afl-fuzz -i corpus/crypto -o output/crypto -M main -- ./fuzz_crypto
# В другом терминале:
afl-fuzz -i corpus/crypto -o output/crypto -S worker1 -- ./fuzz_crypto

# Фаззинг JSON
afl-fuzz -i corpus/json -o output/json -- ./fuzz_json

# Фаззинг пакетов
afl-fuzz -i corpus/packet -o output/packet -- ./fuzz_packet
```

### С ограничением по времени

```bash
# Запуск в течение 24 часов
timeout 86400 afl-fuzz -i corpus/crypto -o output/crypto -- ./fuzz_crypto
```

## Анализ результатов

### Проверка состояния аварийных завершений

```bash
ls output/crypto/default/crashes/
ls output/json/default/crashes/
ls output/packet/default/crashes/
```

### Воспроизведение аварийных завершений

```bash
./fuzz_crypto < output/crypto/default/crashes/id:000000*
```

### Генерация отчёта о покрытии

```bash
# Сборка с покрытием
gcc -fprofile-arcs -ftest-coverage -o fuzz_crypto fuzz_crypto.c -I../include -L../build -lewsp_core

# Запуск с корпусом
for f in output/crypto/default/queue/*; do ./fuzz_crypto < "$f"; done

# Генерация отчёта
gcov fuzz_crypto.c
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
```

## Цели фаззинга

| Тест-жгут | Целевые функции | Области риска |
|---------|------------------|------------|
| fuzz_crypto | SHA256, HMAC, HKDF, XChaCha20 | Переполнение буфера, обработка ключей |
| fuzz_json | Парсинг/построение JSON | Инъекции, DoS, повреждение памяти |
| fuzz_packet | Сериализация/верификация пакетов | Нарушения протокола, атаки на цепочку |

## Непрерывный фаззинг

### Настройка Docker

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

### Интеграция с GitHub Actions

```yaml
name: Fuzzing
on:
  schedule:
    - cron: '0 0 * * *'  # Ежедневно

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

## Ожидаемые результаты

Фаззинг НЕ должен обнаруживать:
- Переполнения буфера (проверка границ реализована)
- Use-after-free (корректное управление памятью)
- Повреждение стека (валидация входных данных)
- Целочисленные переполнения (проверяемая арифметика)

Если обнаружены какие-либо аварийные завершения, пожалуйста, сообщите на security@wakelink.example.com.

## Ресурсы

- [Документация AFL++](https://github.com/AFLplusplus/AFLplusplus)
- [Лучшие практики фаззинга](https://google.github.io/clusterfuzz/reference/coverage-guided/)
- [Руководство по фаззингу OWASP](https://owasp.org/www-community/Fuzzing)
