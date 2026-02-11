# ViperHTTP â€” High-Performance C HTTP Server for MicroPython/ESP32-S3

## Projekt: Kompleksowy Plan Architektury i Implementacji

---

## 1. Wizja Projektu

ViperHTTP to napisany w C, w peĹ‚ni asynchroniczny serwer HTTP/WebSocket, dziaĹ‚ajÄ…cy jako niezaleĹĽny task FreeRTOS na ESP32-S3. Kluczowa innowacja polega na wykorzystaniu architektury dwurdzeniowej ESP32-S3:

- **Core 0**: Serwer HTTP w C + stos WiFi (ESP-IDF)
- **Core 1**: Interpreter MicroPython

Komunikacja miÄ™dzy rdzeniami odbywa siÄ™ przez FreeRTOS queues i ring buffers, co eliminuje blokowanie interpretera Pythona przez operacje I/O sieciowe i odwrotnie.

### Filozofia API: "FastAPI for Microcontrollers"

ViperHTTP Ĺ›wiadomie adoptuje filozofiÄ™ i skĹ‚adniÄ™ **FastAPI** â€” najlepszego wspĂłĹ‚czesnego frameworka webowego Pythona â€” i przenosi jÄ… na grunt MicroPython/embedded. UĹĽytkownik, ktĂłry zna FastAPI, powinien czuÄ‡ siÄ™ jak w domu.

**Kluczowe cechy zaczerpniÄ™te z FastAPI:**

| Cecha FastAPI | Adaptacja ViperHTTP | Uwagi |
|---------------|---------------------|-------|
| `@app.get()`, `@app.post()` dekoratory | âś… Identyczne | BezpoĹ›rednie metody HTTP jako dekoratory |
| Path parameters z typami `{item_id: int}` | âś… `{item_id: int}` | Automatyczna konwersja typĂłw w C |
| Query parameters jako argumenty funkcji | âś… Z wartoĹ›ciami domyĹ›lnymi | Parsowane w C, przekazywane do Pythona |
| `Depends()` â€” Dependency Injection | âś… Uproszczone DI | Bez Annotated (brak w MP), ale peĹ‚ny Depends |
- [x] Role-based guards (require_roles)
| `HTTPException` | âś… Identyczne | Rzucenie wyjÄ…tku = odpowiedĹş bĹ‚Ä™du |
| `APIRouter` â€” grupowanie endpointĂłw | âś… `Router` z prefiksem i deps | Modularyzacja kodu |
| `Request` / `Response` modele | âś… Zoptymalizowane obiekty | Leniwe parsowanie (JSON tylko gdy potrzebny) |
| Background Tasks | âś… `background_tasks.add()` | Przez uasyncio na Core 1 |
| Lifespan events | âś… `@app.on_event("startup")` | Inicjalizacja hardware, cleanup |
| Middleware (CORS, etc.) | âś… C-native + Python | Szybkie w C, elastyczne w Python |
| WebSocket | âś… FastAPI-style dekorator | Z auto ping/pong w C |
| Automatic JSON serialization | âś… Return dict = JSON response | Brak koniecznoĹ›ci `resp.json()` |
| Static Files mount | âś… `app.mount("/static", ...)` | 100% w C, zero Python |

**Czego NIE przenosimy (i dlaczego):**

| Cecha FastAPI | Dlaczego pomijamy |
|---------------|-------------------|
| Pydantic models | Brak Pydantic w MicroPython, za duĹĽo RAM |
| OpenAPI/Swagger auto-docs | Za ciÄ™ĹĽkie dla MCU (~200KB+ JSON) |
| `Annotated[type, Depends()]` | MicroPython nie wspiera typing.Annotated |
| OAuth2 scopes | Zbyt zĹ‚oĹĽone, oferujemy prostszy auth |
| Response model validation | Brak Pydantic; oferujemy rÄ™czne schema |

### Dlaczego to podejĹ›cie jest przeĹ‚omowe?

Aktualnie MicroPython na ESP32 dziaĹ‚a w trybie `CONFIG_FREERTOS_UNICORE=y` (jednordzeniowym). Wszystkie istniejÄ…ce serwery HTTP (Microdot, MicroWebSrv, picoweb) dziaĹ‚ajÄ… w interpreterze Pythona, co oznacza:

- Parsing HTTP odbywa siÄ™ w Pythonie (10-100x wolniej niĹĽ C)
- Serwowanie plikĂłw statycznych wymaga przejĹ›cia przez GC Pythona
- KaĹĽdy request blokuje interpreter
- Brak prawdziwej asynchronicznoĹ›ci â€” `uasyncio` to kooperatywna wielozadaniowoĹ›Ä‡ w jednym wÄ…tku
- API jest zazwyczaj Flask-like (przestarzaĹ‚e, brak DI, brak async-first)

ViperHTTP rozwiÄ…zuje wszystkie te problemy jednoczeĹ›nie, oferujÄ…c jednoczeĹ›nie nowoczesne, FastAPI-like API.

---

## 2. Architektura Dwurdzeniowa â€” Analiza i Uzasadnienie

### 2.1. Dlaczego TAK â€” wykorzystanie dwĂłch rdzeni

**Argumenty za:**

1. **Naturalna separacja obowiÄ…zkĂłw**: WiFi driver ESP-IDF domyĹ›lnie dziaĹ‚a na Core 0 (priorytet 23). Serwer HTTP na tym samym rdzeniu minimalizuje context-switching i komunikacjÄ™ miÄ™dzyrdzeniowÄ… dla operacji sieciowych.

2. **MicroPython nie blokuje sieci**: Gdy Python przetwarza logikÄ™ biznesowÄ… (odczyt czujnikĂłw, obliczenia, generowanie odpowiedzi), serwer HTTP nadal przyjmuje nowe poĹ‚Ä…czenia, serwuje pliki statyczne, obsĹ‚uguje keepalive i ping/pong WebSocket.

3. **Pliki statyczne bez Pythona**: Serwer C na Core 0 moĹĽe bezpoĹ›rednio czytaÄ‡ pliki z flash/VFS (FAT/LittleFS) i streamowaÄ‡ je do klienta z kompresjÄ… gzip, w ogĂłle nie angaĹĽujÄ…c interpretera.

4. **ESP-IDF optymalizacje**: Wg dokumentacji Espressif, WiFi task ma priorytet 23 i jest pinned do Core 0. lwIP TCP/IP task ma priorytet 18. Umieszczenie serwera HTTP na Core 0 pozwala na szybki dostÄ™p do buforĂłw sieciowych bez IPC.

5. **Wzrost przepustowoĹ›ci**: W testach ESP32-S3 z ESP-IDF, optymalna konfiguracja pozwala na ~20 Mbps throughput WiFi. Przy jednordzeniowej pracy MicroPython zjada znacznÄ… czÄ™Ĺ›Ä‡ tego budĹĽetu.

**Potencjalne ryzyka i mitygacja:**

| Ryzyko | Mitygacja |
|--------|-----------|
| Komunikacja miÄ™dzyrdzeniowa dodaje latency | FreeRTOS queues na ESP32-S3 to ~1-5 ÎĽs per operacjÄ™ |
| Synchronizacja pamiÄ™ci miÄ™dzy rdzeniami | UĹĽycie dedykowanych buforĂłw z copy semantics, zero-copy dla plikĂłw statycznych |
| ZwiÄ™kszone zuĹĽycie RAM | DokĹ‚adne profilowanie, pule buforĂłw zamiast malloc |
| ZĹ‚oĹĽonoĹ›Ä‡ debugowania | SEGGER SystemView, ESP-IDF task monitoring, dedykowane logi per-core |
| MicroPython GIL/scheduler | `mp_sched_schedule()` jest thread-safe, ale callbacki wykonujÄ… siÄ™ tylko w main thread MicroPython |

### 2.2. Model PamiÄ™ci

```
â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                    PSRAM (do 8MB)                â”‚
â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚  HTTP Buffer  â”‚  â”‚   MicroPython Heap       â”‚  â”‚
â”‚  â”‚  Pool (Core0) â”‚  â”‚   (Core1)                â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                 Internal SRAM (512KB)            â”‚
â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚ WiFi Bufs  â”‚ â”‚ IPC Queuesâ”‚ â”‚ Stack Core0/1 â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
```

- **IPC Queues**: W Internal SRAM dla minimalnej latencji
- **HTTP Request/Response buffers**: W PSRAM (wiÄ™ksze, ale wolniejsze â€” OK dla HTTP payloads)
- **Connection pool metadata**: W Internal SRAM (maĹ‚y footprint, szybki dostÄ™p)
- **MicroPython heap**: W PSRAM (standardowa konfiguracja)

---

## 3. Architektura SzczegĂłĹ‚owa

### 3.1. Diagram PrzepĹ‚ywu Ĺ»Ä…dania

```
[Klient HTTP]
      â”‚
      â–Ľ
â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ CORE 0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                                                               â”‚
â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚              TCP Accept Loop                        â”‚      â”‚
â”‚  â”‚  (lwIP non-blocking sockets, select/poll)           â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚                     â”‚                                         â”‚
â”‚                     â–Ľ                                         â”‚
â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚           HTTP Parser (zero-copy)                   â”‚      â”‚
â”‚  â”‚  â€˘ Method, URI, Headers parsing                     â”‚      â”‚
â”‚  â”‚  â€˘ Path params extraction + type conversion         â”‚      â”‚
â”‚  â”‚  â€˘ Query params parsing (do osobnych kluczy)        â”‚      â”‚
â”‚  â”‚  â€˘ WebSocket upgrade detection                      â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚                     â”‚                                         â”‚
â”‚            â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”                                â”‚
â”‚            â–Ľ                 â–Ľ                                 â”‚
â”‚   â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                      â”‚
â”‚   â”‚ Static File  â”‚  â”‚  Route Dispatch  â”‚                      â”‚
â”‚   â”‚ Handler      â”‚  â”‚  (C trie lookup  â”‚                      â”‚
â”‚   â”‚ (direct I/O) â”‚  â”‚   + DI resolve)  â”‚                      â”‚
â”‚   â”‚              â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                      â”‚
â”‚   â”‚ â€˘ gzip       â”‚           â”‚                                â”‚
â”‚   â”‚ â€˘ ETag/304   â”‚           â”‚ IPC Queue                      â”‚
â”‚   â”‚ â€˘ Range      â”‚           â”‚ (FreeRTOS)                     â”‚
â”‚   â”‚ â€˘ Streaming  â”‚           â”‚                                â”‚
â”‚   â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”           â”‚                                â”‚
â”‚          â”‚                   â”‚                                â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”Ľâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”Ľâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
           â”‚                   â”‚
           â”‚                   â–Ľ
           â”‚    â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ CORE 1 â”€â”€â”€â”€â”€â”€â”
           â”‚    â”‚                                          â”‚
           â”‚    â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
           â”‚    â”‚  â”‚  Dependency Injection Resolution   â”‚  â”‚
           â”‚    â”‚  â”‚  (Depends chain execution)         â”‚  â”‚
           â”‚    â”‚  â”śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤  â”‚
           â”‚    â”‚  â”‚  C-native middleware execution     â”‚  â”‚
           â”‚    â”‚  â”‚  (CORS, RateLimit â€” resolved in C) â”‚  â”‚
           â”‚    â”‚  â”śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤  â”‚
           â”‚    â”‚  â”‚  Python Handler Execution          â”‚  â”‚
           â”‚    â”‚  â”‚                                     â”‚  â”‚
           â”‚    â”‚  â”‚  @app.get('/api/sensors/{id:int}') â”‚  â”‚
           â”‚    â”‚  â”‚  async def read_sensor(id, db=...) â”‚  â”‚
           â”‚    â”‚  â”‚      return {'temp': db.get(id)}   â”‚  â”‚
           â”‚    â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
           â”‚    â”‚                 â”‚                         â”‚
           â”‚    â”‚                 â”‚ Response via IPC Queue  â”‚
           â”‚    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”Ľâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
           â”‚                     â”‚
           â–Ľ                     â–Ľ
â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ CORE 0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚              Response Serializer                    â”‚      â”‚
â”‚  â”‚  â€˘ Auto JSON serialization (dict/list return)       â”‚      â”‚
â”‚  â”‚  â€˘ gzip compression (optional)                      â”‚      â”‚
â”‚  â”‚  â€˘ Chunked transfer encoding                        â”‚      â”‚
â”‚  â”‚  â€˘ WebSocket frame encoding                         â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚                     â”‚                                         â”‚
â”‚                     â–Ľ                                         â”‚
â”‚              [Klient HTTP]                                    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
```

### 3.2. ModuĹ‚y Systemu

```
viperhttp/
â”śâ”€â”€ core/
â”‚   â”śâ”€â”€ vhttp_server.c/.h          # GĹ‚Ăłwna pÄ™tla serwera, accept, select
â”‚   â”śâ”€â”€ vhttp_parser.c/.h          # Zero-copy HTTP parser
â”‚   â”śâ”€â”€ vhttp_router.c/.h          # Trie-based routing + pattern matching + param types
â”‚   â”śâ”€â”€ vhttp_connection.c/.h      # Connection pool, keepalive mgmt
â”‚   â”śâ”€â”€ vhttp_response.c/.h        # Response builder, auto-JSON serializer
â”‚   â””â”€â”€ vhttp_config.h             # Compile-time configuration
â”‚
â”śâ”€â”€ protocols/
â”‚   â”śâ”€â”€ vhttp_websocket.c/.h       # WebSocket (RFC 6455) â€” upgrade, frames, ping/pong
â”‚   â”śâ”€â”€ vhttp_sse.c/.h             # Server-Sent Events
â”‚   â””â”€â”€ vhttp_multipart.c/.h       # Multipart form parsing
â”‚
â”śâ”€â”€ optimization/
â”‚   â”śâ”€â”€ vhttp_gzip.c/.h            # miniz-based gzip compression
â”‚   â”śâ”€â”€ vhttp_cache.c/.h           # ETag, Last-Modified, 304 Not Modified
â”‚   â”śâ”€â”€ vhttp_static.c/.h          # Static file serving (direct flash read)
â”‚   â””â”€â”€ vhttp_pool.c/.h            # Memory pool allocator (zero-malloc hot path)
â”‚
â”śâ”€â”€ middleware/
â”‚   â”śâ”€â”€ vhttp_middleware.c/.h       # Middleware chain engine
â”‚   â”śâ”€â”€ vhttp_cors.c/.h            # CORS middleware
â”‚   â”śâ”€â”€ vhttp_auth.c/.h            # Basic/Bearer/Digest auth
â”‚   â”śâ”€â”€ vhttp_ratelimit.c/.h       # Rate limiting (token bucket)
â”‚   â”śâ”€â”€ vhttp_logger.c/.h          # Request/Response logging
â”‚   â””â”€â”€ vhttp_security.c/.h        # Security headers (CSP, HSTS, XSS)
â”‚
â”śâ”€â”€ ipc/
â”‚   â”śâ”€â”€ vhttp_ipc.c/.h             # FreeRTOS queue IPC z MicroPythonem
â”‚   â”śâ”€â”€ vhttp_ringbuf.c/.h         # Lock-free ring buffer dla duĹĽych payloadĂłw
â”‚   â””â”€â”€ vhttp_marshal.c/.h         # Serializacja request/response do/z MP
â”‚
â”śâ”€â”€ micropython/
â”‚   â”śâ”€â”€ mod_viperhttp.c            # MicroPython C module â€” binding
â”‚   â”śâ”€â”€ vhttp_mp_app.c/.h          # App class â€” FastAPI-like interface
â”‚   â”śâ”€â”€ vhttp_mp_router.c/.h       # Router class â€” APIRouter equivalent
â”‚   â”śâ”€â”€ vhttp_mp_request.c/.h      # Request object widoczny z Pythona
â”‚   â”śâ”€â”€ vhttp_mp_response.c/.h     # Response object widoczny z Pythona
â”‚   â”śâ”€â”€ vhttp_mp_depends.c/.h      # Dependency Injection engine
â”‚   â”śâ”€â”€ vhttp_mp_exceptions.c/.h   # HTTPException + error handlers
â”‚   â”śâ”€â”€ vhttp_mp_websocket.c/.h    # WebSocket API dla Pythona
â”‚   â””â”€â”€ vhttp_mp_background.c/.h   # Background tasks
â”‚
â””â”€â”€ port/
    â”śâ”€â”€ vhttp_esp32s3.c/.h         # ESP32-S3 specific â€” dual core, PSRAM
    â”śâ”€â”€ vhttp_esp32.c/.h           # ESP32 generic fallback (single core)
    â””â”€â”€ vhttp_filesystem.c/.h      # VFS abstraction (FAT/LittleFS)
```

---

## 4. Mechanizm IPC â€” Komunikacja MicroPython â†” C

### 4.1. Problem

MicroPython ma ograniczenia thread-safety:
- **Nie wolno** tworzyÄ‡ obiektĂłw MicroPython (`mp_obj_new_*`) z innego wÄ…tku niĹĽ MP
- **Nie wolno** wywoĹ‚ywaÄ‡ `mp_call_function_*` z innego wÄ…tku
- `mp_sched_schedule()` jest bezpieczne, ale:
  - Argument musi byÄ‡ waĹĽny w momencie wykonania (nie tymczasowy obiekt na stosie)
  - Kolejka schedulera jest maĹ‚a (domyĹ›lnie 4 sloty)
  - Callback wykonuje siÄ™ "gdy MicroPython ma czas" (w MICROPY_EVENT_POLL_HOOK)

### 4.2. RozwiÄ…zanie: PoĹ›rednik IPC z Dual-Queue

```
                    CORE 0                              CORE 1
              â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”              â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
              â”‚   HTTP Server   â”‚              â”‚   MicroPython   â”‚
              â”‚                 â”‚              â”‚                 â”‚
              â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚  Request Q   â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
              â”‚  â”‚ Prepare   â”‚â”€â”€â”Ľâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”Ľâ”€â–¶â”‚ IPC Loop  â”‚  â”‚
              â”‚  â”‚ IPC Msg   â”‚  â”‚              â”‚  â”‚ (asyncio  â”‚  â”‚
              â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚              â”‚  â”‚  or poll) â”‚  â”‚
              â”‚                 â”‚              â”‚  â”‚           â”‚  â”‚
              â”‚  â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚  Response Q  â”‚  â”‚           â”‚  â”‚
              â”‚  â”‚ Send to   â”‚â—€â”€â”Ľâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”Ľâ”€â”€â”‚           â”‚  â”‚
              â”‚  â”‚ Client    â”‚  â”‚              â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
              â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚              â”‚                 â”‚
              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
```

**Struktura IPC Message:**

```c
typedef struct {
    uint32_t        request_id;     // Unikalny ID ĹĽÄ…dania
    uint8_t         type;           // REQ_HTTP, REQ_WS_MSG, REQ_WS_CONNECT, ...
    uint8_t         method;         // GET, POST, PUT, DELETE, ...
    uint16_t        status_code;    // Dla response
    uint16_t        uri_len;
    uint16_t        headers_len;
    uint32_t        body_len;
    uint32_t        buffer_offset;  // Offset w shared ring buffer
    uint8_t         flags;          // GZIP_OK, KEEPALIVE, CHUNKED, ...
} vhttp_ipc_msg_t;  // 20 bytes â€” mieĹ›ci siÄ™ w FreeRTOS queue item
```

**Dane (URI, headers, body)** nie sÄ… kopiowane do queue â€” zamiast tego trafiajÄ… do **shared ring buffer** w PSRAM, a w queue przesyĹ‚any jest tylko offset. To zapewnia:
- StaĹ‚y rozmiar wiadomoĹ›ci w queue (szybki enqueue/dequeue)
- Zero-copy dla duĹĽych payloadĂłw
- Ring buffer nie wymaga malloc/free

### 4.3. Po stronie MicroPython â€” Event Loop Integration

Zamiast `mp_sched_schedule()` (ograniczony do 4 slotĂłw), uĹĽywamy integracji z `uasyncio`:

```python
# WewnÄ™trzna pÄ™tla IPC (wykonuje siÄ™ w kontekĹ›cie MicroPython na Core 1)
import uasyncio as asyncio

class _IPCBridge:
    """WewnÄ™trzna klasa C module, odpytuje request queue"""

    async def _poll_loop(self):
        while True:
            # C function: sprawdza FreeRTOS queue (non-blocking)
            msg = _viperhttp_native.poll_request()
            if msg is not None:
                await self._dispatch(msg)
            else:
                await asyncio.sleep_ms(1)  # yield to other coroutines

    async def _dispatch(self, msg):
        route = self._router.match(msg['method'], msg['path'])
        if route:
            req = Request(msg)
            try:
                # --- DEPENDENCY INJECTION RESOLUTION ---
                kwargs = await self._resolve_dependencies(route, req)
                # --- PATH PARAMS (already typed by C parser) ---
                kwargs.update(msg.get('path_params', {}))
                # --- HANDLER CALL ---
                result = route.handler(req, **kwargs)
                if asyncio.iscoroutine(result):
                    result = await result
                # --- AUTO SERIALIZATION (FastAPI-style) ---
                response = self._serialize_result(result)
            except HTTPException as e:
                response = e.to_response()
            except Exception as e:
                response = Response(status_code=500, body={'detail': str(e)})
            _viperhttp_native.send_response(response._to_ipc())

    async def _resolve_dependencies(self, route, req):
        """RozwiÄ…zuje Depends() chain â€” jak FastAPI"""
        kwargs = {}
        for param_name, dep in route.dependencies.items():
            if asyncio.iscoroutine(dep):
                kwargs[param_name] = await dep(req)
            else:
                kwargs[param_name] = dep(req)
        return kwargs

    def _serialize_result(self, result):
        """Automatyczna serializacja â€” return dict/list = JSON"""
        if isinstance(result, Response):
            return result
        if isinstance(result, (dict, list)):
            return JSONResponse(content=result)
        if isinstance(result, str):
            return HTMLResponse(content=result)
        return Response(content=str(result))
```

### 4.4. Alternatywna Ĺ›cieĹĽka: Synchroniczny callback z mp_sched_schedule

Dla prostszych przypadkĂłw (bez asyncio), uĹĽywamy mechanizmu BLE-style z MicroPython:

```c
// W module C (na Core 1, w kontekĹ›cie MicroPython task)
static mp_obj_t vhttp_check_pending(void) {
    vhttp_ipc_msg_t msg;
    if (xQueueReceive(request_queue, &msg, 0) == pdTRUE) {
        // Tutaj JESTEĹšMY w kontekĹ›cie MicroPython â€” moĹĽemy tworzyÄ‡ obiekty
        mp_obj_t request_dict = mp_obj_new_dict(8);
        // ... wypeĹ‚nij dict danymi z msg + ring buffer
        return request_dict;
    }
    return mp_const_none;
}
```

---

## 5. FunkcjonalnoĹ›ci SzczegĂłĹ‚owe

### 5.1. HTTP/1.1 Server

| Feature | Opis | Implementacja |
|---------|------|---------------|
| **Pipelining** | Wiele requestĂłw na jednym poĹ‚Ä…czeniu | Ring buffer per-connection |
| **Keep-Alive** | Utrzymywanie poĹ‚Ä…czeĹ„ | Timer + connection pool |
| **Chunked Transfer** | Streaming response | Generator-like API w Pythonie |
| **Content Negotiation** | Accept, Accept-Encoding | Automatyczny gzip jeĹ›li Accept-Encoding: gzip |
| **100 Continue** | Expect header | Automatyczna odpowiedĹş przed body |
| **Range Requests** | Partial content (206) | Dla plikĂłw statycznych |
| **Multipart Upload** | File uploads | Streaming parser, zapis do flash |
| **URL Decoding** | Percent-encoding | Lookup table w C |
| **Query Params** | ?key=value parsing | Zero-copy tokenization, auto-type conversion |
| **Form Data** | application/x-www-form-urlencoded | In-place decode |
| **JSON Body** | application/json | Delegacja do MicroPython `json.loads()` |

### 5.2. WebSocket (RFC 6455)

```
â”Śâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                WebSocket Lifecycle                â”‚
â”‚                                                  â”‚
â”‚  1. HTTP Upgrade Request â”€â”€â”€â”€â”€â”€â–¶ C parser        â”‚
â”‚  2. Sec-WebSocket-Key verify â”€â”€â–¶ SHA1+Base64 (C) â”‚
â”‚  3. 101 Switching Protocols â”€â”€â–¶ C response       â”‚
â”‚  4. Frame decode/encode â”€â”€â”€â”€â”€â”€â–¶ C (masking, etc) â”‚
â”‚  5. Payload to/from Python â”€â”€â–¶ IPC queue         â”‚
â”‚  6. Ping/Pong â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶ Auto w C         â”‚
â”‚  7. Close handshake â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶ C + notify Python â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
```

**Kluczowe**: Ping/pong obsĹ‚ugiwane w peĹ‚ni w C (Core 0) â€” Python nie jest angaĹĽowany. To zapewnia, ĹĽe WebSocket keepalive dziaĹ‚a nawet gdy MicroPython jest zajÄ™ty.

### 5.3. Server-Sent Events (SSE)

SSE utrzymuje poĹ‚Ä…czenie otwarte po stronie C, Python generuje eventy przez IPC. PeĹ‚ne API w sekcji 6.

### 5.4. Static File Server

**ĹšcieĹĽka optymalizacji â€” pliki statyczne w 100% w C:**

```c
// Konfiguracja w MicroPython (FastAPI-style mount):
// app.mount('/static', StaticFiles(directory='/flash/www'), name='static')

static esp_err_t vhttp_serve_static(vhttp_conn_t *conn, const char *path) {
    // 1. SprawdĹş cache (ETag / If-None-Match)
    uint32_t file_hash = vhttp_file_hash(path);
    if (conn->if_none_match == file_hash) {
        return vhttp_send_304(conn);
    }

    // 2. SprawdĹş czy istnieje pre-compressed .gz wersja
    char gz_path[VHTTP_MAX_PATH];
    snprintf(gz_path, sizeof(gz_path), "%s.gz", path);
    bool use_gzip = conn->accept_gzip && vhttp_file_exists(gz_path);

    // 3. Determine MIME type (lookup table)
    const char *mime = vhttp_mime_type(path);

    // 4. Stream plik bezpoĹ›rednio z flash
    FILE *f = fopen(use_gzip ? gz_path : path, "rb");
    struct stat st;
    fstat(fileno(f), &st);

    // 5. WyĹ›lij headers
    vhttp_send_headers(conn, 200, mime, st.st_size, use_gzip);

    // 6. Stream w chunkach (4KB) â€” DMA-friendly
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        vhttp_send_data(conn, buf, n);
    }
    fclose(f);
    return ESP_OK;
}
```

**Optymalizacje plikĂłw statycznych:**
- Pre-compressed `.gz` pliki (raz kompresowane, serwowane wielokrotnie)
- ETag na bazie CRC32 nazwy pliku + rozmiaru + mtime
- MIME type lookup table (nie parsing stringĂłw)
- BezpoĹ›redni odczyt flash â†’ socket, bez PSRAM round-trip
- Opcjonalny in-memory cache dla maĹ‚ych, czÄ™sto uĹĽywanych plikĂłw

### 5.5. Middleware System

```
Request â”€â”€â–¶ [CORS] â”€â”€â–¶ [Auth] â”€â”€â–¶ [RateLimit] â”€â”€â–¶ [Logger] â”€â”€â–¶ Handler
                                                                    â”‚
Response â—€â”€â”€ [CORS] â—€â”€â”€ [Auth] â—€â”€â”€ [RateLimit] â—€â”€â”€ [Logger] â—€â”€â”€â”€â”€â”€â”€â”
```

**Middleware dzielÄ… siÄ™ na dwa typy:**

1. **C-native middleware** (wykonujÄ… siÄ™ na Core 0, zero IPC overhead):
   - CORS â€” dodanie headers do response
   - Security headers â€” CSP, HSTS, X-Frame-Options
   - Rate limiting â€” token bucket w C
   - ETag/caching â€” porĂłwnanie hashĂłw
   - Gzip compression â€” miniz w C
   - Request logging â€” zapis do bufora

2. **Python middleware** (przechodzÄ… przez IPC, ale oferujÄ… elastycznoĹ›Ä‡):
   - Custom auth logic (sprawdzenie w bazie danych)
   - Session management
   - Request/Response transformation
   - Custom validators

### 5.6. Kompresja Gzip

**Strategia trĂłjpoziomowa:**

1. **Pre-compressed static files**: `.gz` wersje tworzone offline/przy uploadzie
2. **On-the-fly compression**: Dla dynamicznych odpowiedzi > 1KB
3. **Streaming compression**: Dla chunked responses

UĹĽycie **miniz** (lightweight, ~10KB code, idealne dla embedded) zamiast zlib.

---

## 6. API MicroPython â€” FastAPI-like Interface

### 6.1. PorĂłwnanie z FastAPI â€” Syntax Side-by-Side

```python
# â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
# â•‘               FastAPI (CPython)                             â•‘
# â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•Ł
#
# from fastapi import FastAPI, Depends, HTTPException, Query, Path
# from fastapi.staticfiles import StaticFiles
# from fastapi.middleware.cors import CORSMiddleware
#
# app = FastAPI(title="My API")
# app.mount("/static", StaticFiles(directory="static"))
# app.add_middleware(CORSMiddleware, allow_origins=["*"])
#
# @app.get("/items/{item_id}")
# async def read_item(item_id: int, q: str = None):
#     return {"item_id": item_id, "q": q}
#
# â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
# â•‘             ViperHTTP (MicroPython) â€” IDENTYCZNA SKĹADNIA   â•‘
# â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•Ł

from viperhttp import ViperHTTP, Depends, HTTPException, Query, Path
from viperhttp.staticfiles import StaticFiles
from viperhttp.middleware import CORSMiddleware

app = ViperHTTP(title="My API")
app.mount("/static", StaticFiles(directory="/flash/www"))
app.add_middleware(CORSMiddleware, allow_origins=["*"])

@app.get("/items/{item_id}")                    # â† Identyczny dekorator!
async def read_item(item_id: int, q: str = None):  # â† Identyczna sygnatura!
    return {"item_id": item_id, "q": q}         # â† return dict = auto JSON!
```

### 6.2. Inicjalizacja Aplikacji i Uruchomienie

```python
from viperhttp import ViperHTTP, Router, Depends, HTTPException
from viperhttp.staticfiles import StaticFiles
from viperhttp.responses import JSONResponse, HTMLResponse, StreamingResponse, RedirectResponse
from viperhttp.middleware import CORSMiddleware

app = ViperHTTP(
    title="Smart Home API",
    version="1.0.0",
    debug=False,
)

# â”€â”€ Static Files (100% C, zero Python overhead) â”€â”€
app.mount("/static", StaticFiles(directory="/flash/www", html=True), name="static")

# â”€â”€ Middleware (FastAPI-style add_middleware) â”€â”€
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    allow_credentials=True,
)

# â”€â”€ Lifespan Events (FastAPI-style) â”€â”€
@app.on_event("startup")
async def startup():
    print("Server starting on Core 0...")
    app.state.db = Database()
    app.state.sensor = BME280()

@app.on_event("shutdown")
async def shutdown():
    app.state.db.close()

# â”€â”€ Uruchomienie (startuje C task na Core 0, IPC bridge na Core 1) â”€â”€
app.run(host="0.0.0.0", port=80)
```

### 6.3. HTTP Method Decorators â€” FastAPI-style

```python
# â”€â”€ GET â”€â”€
@app.get("/")
async def root():
    return {"message": "Hello from ViperHTTP!"}

# â”€â”€ GET z path params + query params â”€â”€
@app.get("/api/sensors/{sensor_id}")
async def read_sensor(
    sensor_id: int,                 # path param â€” auto-konwersja int w C
    include_history: bool = False,  # query param z default
    limit: int = 10,                # query param z default
):
    data = app.state.sensor.read(sensor_id)
    result = {"id": sensor_id, "value": data}
    if include_history:
        result["history"] = get_history(sensor_id, limit)
    return result  # auto-JSON!

# â”€â”€ POST z body â”€â”€
@app.post("/api/sensors/{sensor_id}/config", status_code=201)
async def configure_sensor(sensor_id: int, request: Request):
    body = await request.json()
    # ... validate and apply config
    return {"status": "configured", "sensor_id": sensor_id}

# â”€â”€ PUT â”€â”€
@app.put("/api/devices/{device_id}")
async def update_device(device_id: int, request: Request):
    body = await request.json()
    return {"updated": True, "device_id": device_id}

# â”€â”€ DELETE â”€â”€
@app.delete("/api/devices/{device_id}", status_code=204)
async def delete_device(device_id: int):
    # ... delete logic
    return None  # 204 No Content

# â”€â”€ PATCH â”€â”€
@app.patch("/api/devices/{device_id}")
async def patch_device(device_id: int, request: Request):
    body = await request.json()
    return {"patched": True}
```

### 6.4. Path Parameters z Typami

```python
# â”€â”€ Automatyczna konwersja typĂłw (parsowana w C!) â”€â”€

@app.get("/users/{user_id}")
async def get_user(user_id: int):       # "123" â†’ 123 (int)
    return {"user_id": user_id}

@app.get("/files/{file_path:path}")
async def get_file(file_path: str):     # "docs/readme.md" â†’ peĹ‚na Ĺ›cieĹĽka
    return {"path": file_path}

@app.get("/items/{item_id}/reviews/{review_id}")
async def get_review(item_id: int, review_id: int):   # Wiele params
    return {"item_id": item_id, "review_id": review_id}

# ObsĹ‚ugiwane typy path params:
#   int     â€” walidacja numeryczna w C, 404 jeĹ›li nie-int
#   str     â€” dowolny segment (domyĹ›lny)
#   path    â€” wildcard, Ĺ‚apie Ĺ›cieĹĽki z /
#   float   â€” walidacja float w C
```

### 6.5. Query Parameters z Defaults i WalidacjÄ…

```python
from viperhttp import Query

@app.get("/api/items")
async def list_items(
    page: int = 1,                              # query param, default=1
    limit: int = Query(default=20, ge=1, le=100), # z walidacjÄ… zakresu
    q: str = None,                               # opcjonalny
    sort_by: str = Query(default="name", choices=["name", "date", "price"]),
    active: bool = True,                         # bool: "true"/"1"/"yes" â†’ True
):
    items = get_items(page=page, limit=limit, q=q, sort_by=sort_by, active=active)
    return {
        "items": items,
        "page": page,
        "total": len(items)
    }

# Query() pozwala definiowaÄ‡:
#   default   â€” wartoĹ›Ä‡ domyĹ›lna
#   ge, le    â€” greater/equal, less/equal (numeryczne)
#   min_len, max_len â€” dla stringĂłw
#   choices   â€” dozwolone wartoĹ›ci (enum-like)
#   alias     â€” alternatywna nazwa w URL ("sort-by" â†’ sort_by)
```

### 6.6. Dependency Injection â€” Depends()

```python
from viperhttp import Depends, HTTPException

# â”€â”€ Prosta dependency (jak FastAPI!) â”€â”€
async def get_db():
    """Dependency: zwraca poĹ‚Ä…czenie z bazÄ…"""
    db = Database()
    try:
        yield db        # yield = lifecycle management!
    finally:
        db.close()

async def get_current_user(request: Request):
    """Dependency: weryfikacja tokena"""
    token = request.headers.get("Authorization")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = verify_token(token.replace("Bearer ", ""))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# â”€â”€ UĹĽycie dependencies w handlerze â”€â”€
@app.get("/api/me")
async def get_me(user=Depends(get_current_user)):
    return {"username": user.name, "email": user.email}

@app.get("/api/data")
async def get_data(
    user=Depends(get_current_user),   # auth dependency
    db=Depends(get_db),               # database dependency
    limit: int = 10,                  # query param
):
    return db.query("SELECT * FROM data WHERE user=?", user.id, limit=limit)

# â”€â”€ Chained Dependencies (dependency zaleĹĽy od innej) â”€â”€
async def get_admin_user(user=Depends(get_current_user)):
    """Sub-dependency: sprawdza czy user jest adminem"""
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return user

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, admin=Depends(get_admin_user)):
    # admin jest juĹĽ zweryfikowany przez caĹ‚y chain!
    return {"deleted": user_id}

# â”€â”€ Class-based Dependencies (jak FastAPI) â”€â”€
class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self._store = {}

    async def __call__(self, request: Request):
        ip = request.client.host
        # ... rate limit logic
        if over_limit:
            raise HTTPException(status_code=429, detail="Too many requests")

rate_limit = RateLimiter(max_requests=100, window_seconds=60)

@app.get("/api/public", dependencies=[Depends(rate_limit)])
async def public_endpoint():
    return {"data": "public"}

# â”€â”€ Dependencies w dekoratorze (side-effects, bez return) â”€â”€
@app.get("/api/admin/stats", dependencies=[Depends(get_admin_user)])
async def admin_stats():
    # get_admin_user jest wykonane, ale wynik nie jest przekazywany
    return {"users": 42, "requests_today": 1337}
```

### 6.7. HTTPException â€” ObsĹ‚uga BĹ‚Ä™dĂłw

```python
from viperhttp import HTTPException

@app.get("/api/items/{item_id}")
async def get_item(item_id: int):
    item = find_item(item_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail="Item not found",
            headers={"X-Error": "item_missing"}   # opcjonalne custom headers
        )
    return item

# â”€â”€ Custom Exception Handlers (FastAPI-style) â”€â”€
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "path": request.url.path}
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"error": str(exc)})

# â”€â”€ Catch-all dla nieobsĹ‚uĹĽonych wyjÄ…tkĂłw â”€â”€
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    if app.debug:
        return JSONResponse(status_code=500, content={"error": str(exc), "type": type(exc).__name__})
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

### 6.8. Router â€” Grupowanie EndpointĂłw (APIRouter equivalent)

```python
from viperhttp import Router, Depends

# â”€â”€ sensors_router.py â”€â”€
sensor_router = Router(
    prefix="/api/sensors",
    tags=["sensors"],
    dependencies=[Depends(get_current_user)],  # auth na wszystkie endpointy
)

@sensor_router.get("/")
async def list_sensors(user=Depends(get_current_user)):
    return [{"id": 1, "type": "bme280"}, {"id": 2, "type": "bh1750"}]

@sensor_router.get("/{sensor_id}")
async def get_sensor(sensor_id: int, user=Depends(get_current_user)):
    return {"id": sensor_id, "value": read_sensor(sensor_id)}

@sensor_router.post("/{sensor_id}/calibrate", status_code=202)
async def calibrate(sensor_id: int, admin=Depends(get_admin_user)):
    start_calibration(sensor_id)
    return {"status": "calibration_started"}

# â”€â”€ devices_router.py â”€â”€
device_router = Router(prefix="/api/devices", tags=["devices"])

@device_router.get("/")
async def list_devices():
    return get_all_devices()

# â”€â”€ main.py â€” montowanie routerĂłw â”€â”€
app.include_router(sensor_router)
app.include_router(device_router)

# Wynikowe endpointy:
# GET  /api/sensors/
# GET  /api/sensors/{sensor_id}
# POST /api/sensors/{sensor_id}/calibrate
# GET  /api/devices/
```

### 6.9. WebSocket â€” FastAPI-style

```python
from viperhttp import WebSocket, WebSocketDisconnect

@app.websocket("/ws/sensors")
async def sensor_stream(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # MoĹĽliwoĹ›Ä‡ dwukierunkowej komunikacji
            data = await websocket.receive_text()   # lub receive_json()
            if data == "subscribe":
                while True:
                    reading = read_sensor()
                    await websocket.send_json({"temp": reading})
                    await asyncio.sleep(1)
    except WebSocketDisconnect:
        print("Client disconnected")

# â”€â”€ WebSocket z Depends â”€â”€
@app.websocket("/ws/private")
async def private_ws(
    websocket: WebSocket,
    user=Depends(get_ws_user),   # Auth nawet dla WebSocketĂłw!
):
    await websocket.accept()
    await websocket.send_json({"msg": f"Welcome {user.name}"})
    async for message in websocket.iter_text():
        await websocket.send_text(f"Echo: {message}")

# â”€â”€ Broadcasting helper â”€â”€
class ConnectionManager:
    def __init__(self):
        self.active: list = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: str):
        for ws in self.active:
            await ws.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/chat")
async def chat(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        async for msg in websocket.iter_text():
            await manager.broadcast(msg)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
```

### 6.10. Server-Sent Events

```python
from viperhttp.responses import EventSourceResponse

@app.get("/api/events")
async def event_stream(request: Request):
    async def generate():
        while True:
            data = read_sensor()
            yield {
                "event": "reading",
                "data": {"temp": data, "ts": time.ticks_ms()},
                "id": str(time.ticks_ms()),
            }
            await asyncio.sleep(1)

    return EventSourceResponse(generate())
```

### 6.11. Background Tasks (FastAPI-style)

```python
from viperhttp import BackgroundTasks

async def send_notification(email: str, message: str):
    """Wykonuje siÄ™ PO wysĹ‚aniu response do klienta"""
    # ... wysyĹ‚anie emaila/push notification
    print(f"Notification sent to {email}")

async def write_log(action: str, user_id: int):
    """Logowanie w tle"""
    with open("/flash/audit.log", "a") as f:
        f.write(f"{time.ticks_ms()} {action} user={user_id}\n")

@app.post("/api/alerts")
async def create_alert(
    request: Request,
    background_tasks: BackgroundTasks,   # automatycznie injected!
    user=Depends(get_current_user),
):
    body = await request.json()

    # Dodaj zadania w tle â€” wykonajÄ… siÄ™ PO response
    background_tasks.add_task(send_notification, user.email, body["message"])
    background_tasks.add_task(write_log, "create_alert", user.id)

    return {"status": "alert created"}  # Response wysyĹ‚any NATYCHMIAST
```

### 6.12. Response Types

```python
from viperhttp.responses import (
    JSONResponse, HTMLResponse, PlainTextResponse,
    RedirectResponse, StreamingResponse, FileResponse,- [x] `StreamingResponse`
    RedirectResponse, StreamingResponse, FileResponse,- [ ] `FileResponse`
    RedirectResponse, StreamingResponse, FileResponse,- [ ] `RedirectResponse`
    EventSourceResponse, Response
)

# â”€â”€ Automatyczna serializacja (return = JSONResponse) â”€â”€
@app.get("/auto")
async def auto():
    return {"key": "value"}   # â†’ JSONResponse({"key": "value"})

# â”€â”€ Explicit Response Types â”€â”€
@app.get("/html")
async def html_page():
    return HTMLResponse("<h1>Hello</h1>")

@app.get("/redirect")
async def redirect():
    return RedirectResponse(url="/new-location", status_code=301)

@app.get("/file")
async def download_file():
    return FileResponse(
        path="/flash/data.csv",
        filename="data.csv",            # Content-Disposition header
        media_type="text/csv"
    )

# â”€â”€ Streaming â”€â”€
@app.get("/stream")
async def stream():
    async def generate():
        for i in range(100):
            yield f"chunk {i}\n"
            await asyncio.sleep_ms(100)

    return StreamingResponse(generate(), media_type="text/plain")

# â”€â”€ Custom Response â”€â”€
@app.get("/custom")
async def custom():
    return Response(
        content="custom body",
        status_code=200,
        headers={"X-Custom": "value"},
        media_type="text/plain"
    )
```

### 6.13. Middleware â€” FastAPI-style

```python
from viperhttp.middleware import CORSMiddleware, TrustedHostMiddleware

# â”€â”€ Built-in middleware (konfigurowane w C â€” maksymalna wydajnoĹ›Ä‡) â”€â”€
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myapp.com", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
    max_age=3600,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*.myapp.com"])

# â”€â”€ Custom Python middleware (FastAPI-style BaseHTTPMiddleware) â”€â”€
from viperhttp.middleware import BaseHTTPMiddleware

class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.ticks_ms()
        response = await call_next(request)
        elapsed = time.ticks_diff(time.ticks_ms(), start)
        response.headers["X-Process-Time"] = str(elapsed)
        return response

app.add_middleware(TimingMiddleware)

# â”€â”€ Prostsza forma dekoratorowa â”€â”€
@app.middleware("http")
async def add_custom_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "ViperHTTP"
    return response
```

### 6.14. Obiekt Request (rozbudowany)

```python
class Request:
    # â”€â”€ Properties (lazy-parsed, cache'owane) â”€â”€
    method: str                     # 'GET', 'POST', ...
    url: URL                        # URL object z path, query, fragment
    headers: Headers                # Case-insensitive dict
    query_params: QueryParams       # MultiDict z query string
    path_params: dict               # Typed path params z routera
    client: Address                 # .host, .port klienta
    state: State                    # Custom state dla middleware

    # â”€â”€ Async methods (body parsing) â”€â”€
    async def json(self) -> dict
    async def form(self) -> FormData
    async def body(self) -> bytes
    async def stream(self) -> AsyncGenerator[bytes]

    # â”€â”€ Properties (convenience) â”€â”€
    @property
    def cookies(self) -> dict
    @property
    def content_type(self) -> str

class URL:
    path: str                       # '/api/items'
    query: str                      # 'page=1&limit=10'
    fragment: str                   # 'section1'
    scheme: str                     # 'http'

    def __str__(self) -> str        # PeĹ‚ny URL
```

### 6.15. File Upload (FastAPI-style)

```python
from viperhttp import UploadFile

@app.post("/api/upload")
async def upload(
    file: UploadFile,               # automatycznie parsowane z multipart
    user=Depends(get_current_user),
):
    contents = await file.read()
    # lub streaming:
    async for chunk in file:
        process_chunk(chunk)

    return {
        "filename": file.filename,
        "size": file.size,
        "content_type": file.content_type
    }

# â”€â”€ Wiele plikĂłw â”€â”€
@app.post("/api/upload-many")
async def upload_many(files: list[UploadFile]):
    results = []
    for f in files:
        data = await f.read()
        save_to_flash(f.filename, data)
        results.append({"name": f.filename, "size": f.size})
    return results
```

### 6.16. PeĹ‚ny PrzykĹ‚ad â€” Smart Home API

```python
from viperhttp import ViperHTTP, Router, Depends, HTTPException, BackgroundTasks, WebSocket
from viperhttp.staticfiles import StaticFiles
from viperhttp.middleware import CORSMiddleware
from viperhttp.responses import EventSourceResponse

import uasyncio as asyncio
import json

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  App + Middleware
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app = ViperHTTP(title="Smart Home", version="1.0.0")

app.mount("/", StaticFiles(directory="/flash/www", html=True), name="frontend")
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Dependencies
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async def get_current_user(request: Request):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(401, "Missing token")
    user = verify_jwt(token)
    if not user:
        raise HTTPException(401, "Invalid token")
    return user

def get_sensor_manager():
    return app.state.sensors

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Sensor Router
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
sensors = Router(prefix="/api/sensors", tags=["sensors"])

@sensors.get("/")
async def list_all(mgr=Depends(get_sensor_manager)):
    return [{"id": s.id, "type": s.type} for s in mgr.all()]

@sensors.get("/{sensor_id}")
async def read_one(sensor_id: int, mgr=Depends(get_sensor_manager)):
    sensor = mgr.get(sensor_id)
    if not sensor:
        raise HTTPException(404, f"Sensor {sensor_id} not found")
    return {"id": sensor_id, "value": sensor.read(), "unit": sensor.unit}

@sensors.post("/{sensor_id}/config", dependencies=[Depends(get_current_user)])
async def configure(sensor_id: int, request: Request, background_tasks: BackgroundTasks):
    config = await request.json()
    apply_config(sensor_id, config)
    background_tasks.add_task(log_config_change, sensor_id, config)
    return {"status": "applied"}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  WebSocket â€” Live Sensor Data
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@app.websocket("/ws/live")
async def live_data(ws: WebSocket):
    await ws.accept()
    try:
        # Klient wysyĹ‚a JSON z konfiguracjÄ… subskrypcji
        config = await ws.receive_json()
        sensor_ids = config.get("sensors", [1])
        interval = config.get("interval_ms", 1000)

        while True:
            readings = {sid: read_sensor(sid) for sid in sensor_ids}
            await ws.send_json({"ts": time.ticks_ms(), "data": readings})
            await asyncio.sleep_ms(interval)
    except Exception:
        pass

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  SSE â€” Event Stream
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@app.get("/api/events")
async def events():
    async def stream():
        while True:
            yield {"event": "sensor", "data": {"temp": read_temp()}}
            await asyncio.sleep(2)
    return EventSourceResponse(stream())

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Startup + Run
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@app.on_event("startup")
async def startup():
    app.state.sensors = SensorManager()
    print(f"ViperHTTP running on {app.host}:{app.port}")

app.include_router(sensors)
app.run(host="0.0.0.0", port=80)
```

---

## 7. Optymalizacje Kluczowe

### 7.1. Zero-Copy HTTP Parser

Wzorowany na **llhttp** (Node.js) / **picohttpparser** (H2O):

```c
// Parser nie kopiuje danych â€” zwraca wskaĹşniki do oryginalnego bufora
typedef struct {
    const char *method;      uint8_t method_len;
    const char *uri;         uint16_t uri_len;
    const char *path;        uint16_t path_len;
    const char *query;       uint16_t query_len;
    struct {
        const char *name;    uint8_t name_len;
        const char *value;   uint16_t value_len;
    } headers[VHTTP_MAX_HEADERS];
    uint8_t num_headers;
    const char *body;        uint32_t body_len;

    // Path params (extracted during routing)
    struct {
        const char *name;    uint8_t name_len;
        const char *value;   uint16_t value_len;
        uint8_t type;        // PARAM_STR, PARAM_INT, PARAM_FLOAT, PARAM_PATH
    } path_params[VHTTP_MAX_PATH_PARAMS];
    uint8_t num_path_params;
} vhttp_parsed_request_t;

// Parsing to pointer arithmetic, zero malloc
int vhttp_parse_request(const char *buf, size_t len, vhttp_parsed_request_t *req);

// Path param type conversion happens in C (before IPC to Python)
// "123" â†’ mp_obj_new_int(123) jest tworzony po stronie MicroPython
// ale C przesyĹ‚a raw value + type tag, oszczÄ™dzajÄ…c parsing w Python
```

### 7.2. Memory Pool Allocator

```c
// Pre-allocated pool â€” zero malloc na hot path
#define VHTTP_MAX_CONNECTIONS   8
#define VHTTP_RECV_BUF_SIZE     4096
#define VHTTP_SEND_BUF_SIZE     8192

typedef struct {
    vhttp_conn_t    connections[VHTTP_MAX_CONNECTIONS];
    uint8_t         recv_bufs[VHTTP_MAX_CONNECTIONS][VHTTP_RECV_BUF_SIZE];
    uint8_t         send_bufs[VHTTP_MAX_CONNECTIONS][VHTTP_SEND_BUF_SIZE];
    uint32_t        free_mask;  // Bitmask wolnych slotĂłw
} vhttp_pool_t;

// Alokacja: O(1) â€” count leading zeros
vhttp_conn_t* vhttp_pool_alloc(vhttp_pool_t *pool) {
    int idx = __builtin_ctz(pool->free_mask);  // Pierwsza wolna pozycja
    pool->free_mask &= ~(1u << idx);
    return &pool->connections[idx];
}
```

### 7.3. Trie-based Router z Type-aware Path Params

```c
// Routing O(n) wzglÄ™dem dĹ‚ugoĹ›ci URI, nie liczby routes
// ObsĹ‚uguje FastAPI-style parametry: /api/users/{user_id:int}/posts/{post_id}
typedef struct vhttp_trie_node {
    char                    segment[32];
    uint8_t                 segment_len;
    uint8_t                 param_type;     // NONE, STRING, INT, FLOAT, PATH
    char                    param_name[24]; // Nazwa parametru z dekoratora
    vhttp_handler_t         handlers[8];    // per-method (GET=0, POST=1, ...)
    vhttp_dep_chain_t       *dependencies;  // Depends() chain metadata
    struct vhttp_trie_node  *children[16];
    uint8_t                 num_children;
    uint16_t                expected_status; // status_code z dekoratora
} vhttp_trie_node_t;

// Rejestracja route'a z Pythona â†’ C
// @app.get("/items/{item_id}") â†’ vhttp_router_add("GET", "/items/{item_id}", ...)
// C parser wyciÄ…ga: segment="items", child: param_type=INT, param_name="item_id"
```

### 7.4. Connection Pooling i Keep-Alive

```c
typedef struct {
    int             sockfd;
    uint32_t        last_activity;      // ticks
    uint16_t        requests_served;    // dla keep-alive limit
    uint8_t         state;              // IDLE, READING, PROCESSING, WRITING
    uint8_t         flags;              // KEEPALIVE, WEBSOCKET, SSE
    vhttp_parsed_request_t  current_req;
    uint8_t         *recv_buf;          // Z pool
    uint8_t         *send_buf;          // Z pool
    size_t          recv_pos;
    size_t          send_pos;
    size_t          send_len;
} vhttp_conn_t;
```

### 7.5. Tabelka PorĂłwnawcza Optymalizacji

| Aspekt | Microdot (Python) | ViperHTTP (C+Python) | Przyspieszenie |
|--------|-------------------|----------------------|----------------|
| HTTP parsing | ~500 ÎĽs | ~5 ÎĽs | ~100x |
| Routing (10 routes) | ~100 ÎĽs | ~2 ÎĽs | ~50x |
| Static file 10KB | ~15 ms | ~0.5 ms | ~30x |
| Static file 100KB | ~150 ms | ~3 ms | ~50x |
| JSON response | ~2 ms | ~0.5 ms* | ~4x |
| WebSocket frame | ~200 ÎĽs | ~3 ÎĽs | ~70x |
| Concurrent connections | 1-3 | 8+ | 3-8x |
| Memory per connection | ~8-16 KB | ~5 KB (pool) | ~2-3x less |
| DI resolution | N/A (brak) | ~50 ÎĽs | N/A â€” nowa funkcja |

*JSON serializacja nadal w Pythonie, ale bez HTTP overhead

---

## 8. Konfiguracja Compile-Time

```c
// vhttp_config.h â€” dostosowywane przez sdkconfig / menuconfig

// Serwer
#define VHTTP_MAX_CONNECTIONS       8       // Max jednoczesnych poĹ‚Ä…czeĹ„
#define VHTTP_MAX_HEADERS           24      // Max headers per request
#define VHTTP_MAX_URI_LEN           512     // Max dĹ‚ugoĹ›Ä‡ URI
#define VHTTP_MAX_HEADER_SIZE       4096    // Max sumaryczny rozmiar headers
#define VHTTP_MAX_BODY_SIZE         65536   // Max body (streaming powyĹĽej)
#define VHTTP_MAX_PATH_PARAMS       8       // Max path params per route
#define VHTTP_KEEPALIVE_TIMEOUT_S   30      // Keep-alive timeout
#define VHTTP_KEEPALIVE_MAX_REQ     100     // Max requestĂłw per keep-alive

// Task
#define VHTTP_TASK_STACK_SIZE       8192    // Stack serwera (Core 0)
#define VHTTP_TASK_PRIORITY         12      // NiĹĽej niĹĽ WiFi (23), wyĹĽej niĹĽ idle
#define VHTTP_TASK_CORE             0       // Pinned do Core 0

// IPC
#define VHTTP_IPC_REQUEST_QUEUE_LEN     16
#define VHTTP_IPC_RESPONSE_QUEUE_LEN    16
#define VHTTP_IPC_RINGBUF_SIZE          32768   // 32KB shared ring buffer

// Kompresja
#define VHTTP_GZIP_ENABLED          1
#define VHTTP_GZIP_MIN_SIZE         1024
#define VHTTP_GZIP_LEVEL            6
#define VHTTP_GZIP_BUF_SIZE         4096

// WebSocket
#define VHTTP_WS_MAX_CONNECTIONS    4
#define VHTTP_WS_MAX_FRAME_SIZE     4096
#define VHTTP_WS_PING_INTERVAL_S    30
#define VHTTP_WS_PONG_TIMEOUT_S     10

// Cache
#define VHTTP_STATIC_CACHE_ENTRIES  16      // In-memory cache dla maĹ‚ych plikĂłw
#define VHTTP_STATIC_CACHE_MAX_SIZE 2048    // Max rozmiar cached pliku

// Dependency Injection
#define VHTTP_MAX_DEPENDENCIES      16      // Max dependencies per route
#define VHTTP_MAX_DEP_CHAIN_DEPTH   8       // Max zagnieĹĽdĹĽenie Depends
```

---

## 9. Integracja z MicroPython Build System

### 9.1. Jako User C Module

```cmake
# micropython.cmake
add_library(viperhttp INTERFACE)

target_sources(viperhttp INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/core/vhttp_server.c
    ${CMAKE_CURRENT_LIST_DIR}/core/vhttp_parser.c
    ${CMAKE_CURRENT_LIST_DIR}/core/vhttp_router.c
    ${CMAKE_CURRENT_LIST_DIR}/micropython/mod_viperhttp.c
    ${CMAKE_CURRENT_LIST_DIR}/micropython/vhttp_mp_app.c
    ${CMAKE_CURRENT_LIST_DIR}/micropython/vhttp_mp_depends.c
    ${CMAKE_CURRENT_LIST_DIR}/micropython/vhttp_mp_exceptions.c
    # ... wszystkie pliki .c
)

target_include_directories(viperhttp INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(viperhttp INTERFACE
    usermod
)
```

### 9.2. Modyfikacja sdkconfig

```ini
# WĹ‚Ä…czenie dual-core (wymagane!)
CONFIG_FREERTOS_UNICORE=n

# Optymalizacje wydajnoĹ›ci
CONFIG_COMPILER_OPTIMIZATION_PERF=y
CONFIG_ESPTOOLPY_FLASHMODE_QIO=y
CONFIG_ESPTOOLPY_FLASHFREQ_80M=y

# lwIP tuning
CONFIG_LWIP_TCP_MSS=1460
CONFIG_LWIP_TCP_SND_BUF_DEFAULT=5840
CONFIG_LWIP_TCP_WND_DEFAULT=5840
CONFIG_LWIP_TCP_RECVMBOX_SIZE=12
CONFIG_LWIP_TCP_ACCEPTMBOX_SIZE=8
CONFIG_LWIP_TCPIP_RECVMBOX_SIZE=32
CONFIG_LWIP_SO_REUSE=y

# PSRAM (ESP32-S3 z PSRAM)
CONFIG_ESP32S3_SPIRAM_SUPPORT=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_SPEED_80M=y
```

---

## 10. Plan Implementacji â€” Fazy

### Faza 1: Fundament + Minimal FastAPI (5-7 tygodni)
- [x] Zero-copy HTTP parser (standalone, testowany na PC)
- [x] Memory pool allocator
- [x] Podstawowy TCP accept + select loop
- [x] Connection management (keepalive, timeout)
- [x] Trie router z **typed path params** (`{id:int}`, `{name:str}`, `{path:path}`)
- [x] Integracja z ESP-IDF jako FreeRTOS task na Core 0
- [x] Podstawowy IPC (FreeRTOS queue, request/response)
- [x] MicroPython C module: **`@app.get()`, `@app.post()`** dekoratory
- [x] Auto-JSON serialization (return dict â†’ JSONResponse)
- [x] **`HTTPException`** basic handling
- [x] `app.run()` startujÄ…cy dual-core setup

### Faza 2: Core Features + DI (5-7 tygodni)
- [x] **Dependency Injection** â€” `Depends()` z chain resolution
- [x] **Query params** z typami i defaults
- [x] Static file serving (direct flash read) + `app.mount()`
- [x] Gzip compression (miniz)
- [x] ETag / 304 Not Modified
- [x] WebSocket handshake + frame en/decode + FastAPI-style `@app.websocket()`
- [x] WebSocket ping/pong (auto w C)
- [x] JSON body parsing (`await request.json()`)
- [x] Form data / multipart parser
- [x] Cookie parser
- [x] **`Router`** (APIRouter equivalent) z `app.include_router()`
- [x] Router storage refactor: dynamic edge pool (usuniety limit per-node children, wieksze limity tras)
- [x] Background Tasks â€” `BackgroundTasks`

### Faza 3: Middleware + ProtokoĹ‚y + Responses (4-5 tygodni)
- [x] **`app.add_middleware()`** â€” FastAPI-style registration
- [x] **`CORSMiddleware`** (C-native)
- [x] Rate limiter (token bucket, C-native)
- [x] Security headers middleware (`TrustedHostMiddleware`)
- [x] Custom Python middleware â€” `BaseHTTPMiddleware`
- [x] **`@app.middleware("http")`** dekorator
- [x] Custom function middleware with priority (MicroPython)
- [x] Session middleware + VFS store (CSRF, LRU compaction)
- [x] SSE â€” `EventSourceResponse`
- [x] `StreamingResponse`
- [x] `FileResponse`
- [x] `RedirectResponse`
- [x] Chunked transfer encoding
- [x] Range requests (206 Partial Content)
- [x] `UploadFile` â€” FastAPI-style file uploads

### Faza 4: Polish + Events + Advanced (4-5 tygodni)
- [x] **Lifespan events** â€” `@app.on_event("startup"/"shutdown")`
- [x] **Exception handlers** â€” `@app.exception_handler()`
- [x] `uasyncio` deep integration (async generators runtime-gated, yield dependencies)
- [x] WebSocket broadcast helper (`ConnectionManager`)
- [x] `app.state` â€” shared state object
- [x] `Request.state` â€” per-request state (middleware â†’ handler)
- [x] Class-based dependencies (`__call__` pattern)
- [x] Logging system (C-native, konfigurowalny level)
- [ ] Dokumentacja API + examples
- [ ] Benchmarki porĂłwnawcze vs Microdot

### Faza 5: Zaawansowane (opcjonalne)
- [x] HTTPS (mbedTLS, ESP-IDF integration)
- [ ] HTTP/2 (jeĹ›li RAM pozwoli)
- [x] OTA update via HTTP endpoint
- [x] Template engine (C-side, Jinja2-like subset)
- [x] Auto-generated API docs (lekka wersja, mini-Swagger)

#### HTTPS (plan wykonawczy)
- [x] etap 1: runtime API + konfiguracja cert/key (MicroPython: `viperhttp.start(..., https=True, cert_pem=..., key_pem=...)`, `viperhttp.configure_https(...)`, oraz `bridge/app.run(..., tls_cert_path=..., tls_key_path=...)`)
- [x] etap 1: TLS handshake na poĹ‚Ä…czenie, domyĹ›lnie wyĹ‚Ä…czone (`https=False`)
- [x] etap 1: telemetria HTTPS w `server_stats` (`https_enabled`, `https_handshake_ok`, `https_handshake_fail`)
- [x] etap 2: peĹ‚na zgodnoĹ›Ä‡ event-loop + HTTPS (bez fallbacku do worker-compat)
- [x] etap 2: WebSocket over HTTPS (WSS) wiring w runtime (TLS-aware WS send/recv + handoff cleanup)
- [x] etap 2: WSS bez regresji stabilnoĹ›ci (walidacja urzÄ…dzeniowa)
- [x] etap 3: benchmark i profile pamiÄ™ci (TLS overhead, handshake latency, keep-alive TLS)

#### HTTP/2 (plan wykonawczy)
- [x] etap 0: runtime API + optional toggle (`viperhttp.start(..., http2=True/False, http2_max_streams=...)`, `viperhttp.configure_http2(...)`, `viperhttp.http2_status()`)
- [x] etap 0: PSRAM-first metadata slots dla stream/session bookkeeping + telemetry (`http2_*` w `server_stats`)
- [x] etap 0: detekcja preface `PRI * HTTP/2.0...` i kontrolowane zakoĹ„czenie binarnym `SETTINGS + GOAWAY` (bez regresji HTTP/1.1)
- [x] etap 1: parser ramek HTTP/2 + HPACK decode (statyczna+dynam. tabela)
- [x] etap 1: mapowanie HEADERS/DATA -> obecny routing/IPC i odpowiedĹş HEADERS/DATA
- [ ] etap 2: flow-control, multiple streams, priorytety, RST_STREAM/GOAWAY, keep-alive
- [x] etap 2: ALPN `h2` dla HTTPS i h2c upgrade dla HTTP
- [ ] etap 3: walidacja kompatybilnoĹ›ci (curl/nghttp2/browser), benchmarki i profile pamiÄ™ci

#### OTA (plan wykonawczy)
- [x] etap 0: runtime manager OTA (MicroPython, `esp32.Partition`) z pelnym lifecycle sesji: `ota_status`, `ota_begin`, `ota_write`, `ota_finalize`, `ota_abort`, `ota_apply`, `ota_mark_app_valid`
- [x] etap 0: walidacja rozmiaru i integralnosci (`expected_size`, `expected_sha256`) + progres i diagnostyka (`last_result`, `last_error`, metryki sesji)
- [x] etap 0: bezpieczny model zapisu do slotu update (sequential writes, erase-per-block, brak przelaczenia boot bez jawnego `set_boot=True`)
- [x] etap 1: endpointy HTTP OTA (FastAPI-style) instalowane automatycznie/optional:
- [x] `GET /ota/status`
- [x] `POST /ota/begin`
- [x] `POST /ota/chunk`
- [x] `POST /ota/finalize`
- [x] `POST /ota/abort`
- [x] `POST /ota/upload` (one-shot upload)
- [x] `POST /ota/mark-valid`
- [x] etap 1: kontrola dostepu tokenem (`X-OTA-Token` lub query token) + jednolity format bledow JSON (`status_code`, `detail`)
- [x] etap 1: integracja `app.run(...)` bez recznego bridge:
- [x] `ota=True/False`, `ota_prefix`, `ota_token`, `ota_token_header`, `ota_token_query`
- [x] etap 2: integracja z API aplikacji:
- [x] auto-install przez `app.run(..., ota=True, ...)` oraz reczna instalacja przez `viperhttp_ota.install_ota_routes(app, ...)`
- [x] endpoint diagnostyczny demo: `GET /debug/ota-status`
- [x] etap 3: testy:
- [x] host mock test logiki OTA i endpointow (`tools/host_ota_mock_test.py`)
- [x] device smoke test OTA na COM14 bez zmiany boot partition (`tools/device_ota_test.py`)
- [x] host/device E2E OTA over HTTP(S): chunked upload firmware przez endpointy OTA + finalize `set_boot=True,reboot=True` i walidacja partycji po restarcie (`tools/ota_e2e_test.py`)
- [x] rollback smoke-check po drugim restarcie (po `ota_mark_app_valid`) z weryfikacja, ze aktywna partycja OTA zostaje utrzymana (`tools/ota_e2e_test.py --serial-port COM14`)

#### HTTP/2 Full (event-loop async, execution plan)
- [x] H2-FULL-00: observability baseline
- [x] rozszerzyc `server_stats` o metryki HTTP/2 (RST, kody bledow, przeciacia protokolu, limity streamow)
- [x] dodac stabilne klucze w API stats (bez obcinania nazw) i test parsowania `/debug/server-stats`
- [ ] H2-FULL-01: hard requirement - async event-loop as primary runtime
- [x] dodac telemetry fallbacku (`http2_task_fallback_used`) aby mierzyc odejscie od worker/task modelu
- [x] wydzielic HTTP/2 IPC `enqueue` i `wait` do helperow (przygotowanie pod nieblokujacy wait w event-loop)
- [x] usunac zaleznosc od per-connection worker/task dla HTTP/2 w trybie event-loop
- [x] dodac `short_idle_after_response` dla sciezki event-loop (krotki slice po odpowiedzi zamiast dlugiego idle wait)
- [x] dodac `VHTTP_HTTP2_EVENT_LOOP_FIRST_REQ_WAIT_MS` i podpiac timeout oczekiwania na pierwszy request bez blokowania petli
- [x] dodac async `WAIT_IPC` polling dla HTTP/2 (single in-flight stream per polaczenie, bez blokowania petli do timeoutu)
- [x] domknac lifecycle `pending` (cancel in-flight IPC przy timeout/RST/teardown + release slotu streamu)
- [ ] utrzymac non-blocking IO + kroki state machine per polaczenie (tick w petli event-loop)
- [x] wprowadzic per-connection `h2_ctx` w event-loop i cleanup lifecycle przy zwalnianiu slotu
- [x] dodac parser ramek HTTP/2 z bufora (`try_read_buffered_frame`) i budget krokow per tick
- [x] domknac non-blocking TX dla H2 w event-loop (`h2_ctx` tx-queue + flush po `wfds`); sciezka worker-compat pozostaje blokujaca
- [x] fallback worker-compat tylko jako tryb awaryjny, domyslnie wylaczony dla HTTP/2
- [ ] H2-FULL-02: pelna maszyna stanow streamow
- [x] stany RFC: `idle/open/half-closed(local|remote)/closed` + walidacja przejsc
- [ ] poprawne zachowanie przy interleaving ramek z wielu streamow
- [x] interleaving baseline: przy aktywnym `pending` drugi stream moze byc przyjety/zbuforowany i odpalony po zakonczeniu poprzedniego (bez `GOAWAY`)
- [x] interleaving queue v2: przy aktywnym `pending` mozna zbuforowac wiele `ready` streamow (bounded queue) i dispatchowac sekwencyjnie bez zrywania sesji
- [x] interleaving DATA v3: aktywny stream moze byc tymczasowo odlozony (buffered) i wznowiony po ramkach innego streamu; dodano host regression `tools/http2_interleave_data_test.py` (POST body split + GET interleave na jednym polaczeniu)
- [x] cleanup per-stream bez wyciekow (HPACK refs, body buffers, sloty)
- [ ] H2-FULL-03: flow-control (connection + stream)
- [x] baseline flow-control v1: sesja/stream trzymaja okna RX/TX; `DATA` konsumuje RX window i odswieza je przez `WINDOW_UPDATE` (conn+stream) bez blokowania event-loop
- [x] walidacja `WINDOW_UPDATE`: increment=0 => `FLOW_CONTROL_ERROR` (`GOAWAY` dla conn, stream-error dla stream), overflow guard dla update okien
- [x] `SETTINGS_INITIAL_WINDOW_SIZE` od peera aktualizuje tx-window bookkeeping dla aktywnych streamow (delta na wszystkie sloty + overflow guard)
- [ ] okna RX/TX per stream i per connection, `WINDOW_UPDATE`, `INITIAL_WINDOW_SIZE`
- [ ] limity i backpressure bez blokowania event-loop
- [ ] ochrona przed overflow okien i nieprawidlowymi update
- [ ] H2-FULL-04: framing compliance
- [ ] poprawna obsluga `CONTINUATION`, padding, priority fields, trailers
- [x] twarda walidacja kolejnosci `CONTINUATION` (jesli oczekiwany, kazda inna ramka powoduje `GOAWAY(PROTOCOL_ERROR)`)
- [x] host regression dla `CONTINUATION` ordering violation: `tools/http2_continuation_guard_test.py` (weryfikacja przez frame/counter `http2_goaway_sent`)
- [ ] walidacja kolejnosci ramek i `END_HEADERS`/`END_STREAM` dla wielu streamow
- [ ] precyzyjne mapowanie bledow na `RST_STREAM` vs `GOAWAY`
- [ ] H2-FULL-05: priorities i fairness
- [ ] parsowanie `PRIORITY` (co najmniej bezpieczne utrzymanie grafu zaleznosci)
- [ ] scheduler fairness: brak starvation streamow przy mieszanym ruchu
- [ ] H2-FULL-06: keep-alive, drain i graceful shutdown
- [ ] `GOAWAY(last_stream_id)` + dokańczanie in-flight streamow
- [ ] timeouty idle/headers/data i deterministiczne zamykanie polaczen
- [ ] H2-FULL-07: compatibility matrix
- [ ] testy z `curl --http2`, nghttp2 (`nghttp`), klient python, przegladarka (HTTPS+ALPN)
- [ ] testy h2c upgrade oraz prior-knowledge bez regresji HTTP/1.1/HTTPS/WSS
- [ ] H2-FULL-08: performance + memory gates
- [ ] benchmark: throughput + p50/p95/p99, CPU core0/core1, RAM/PSRAM
- [ ] soak 6h i 24h (brak crash, leak, deadlock), burst tests i chaos reconnect
- [ ] H2-FULL-09: release criteria (DoD)
- [ ] 0 panic/crash w soak 24h, 0 known protocol regressions
- [ ] kompatybilnosc matrix pass, limity pamieci dotrzymane, event-loop async jako default

---

### Faza 5A: Template Engine (C-side, Jinja2-like subset) - execution plan
- [x] TE-01: Freeze syntax + compatibility profile (explicit Jinja subset, no Python eval)
- [x] TE-02: Public API (MicroPython)
- [x] `viperhttp.TemplateResponse(path, context=None, status_code=200, headers=None, content_type="text/html; charset=utf-8")`
- [x] `viperhttp.render_template(path, context=None)` for tests and small payloads
- [x] `viperhttp.template_clear_cache(path=None)`, `viperhttp.template_stats()`
- [x] TE-03: C parser + compiler pipeline
- [x] lexical scanner (zero-copy tokens over template buffer)
- [x] parser to compact AST/bytecode (no dynamic eval)
- [x] compile-time validation with deterministic error messages (line/column)
- [x] TE-04: Runtime engine
- [x] escaped output by default for `{{ ... }}` (HTML escaping)
- [x] raw output only via explicit marker/filter
- [x] conditionals: `if / elif / else`
- [x] loops: `for item in list`, loop metadata (`index`, `first`, `last`)
- [x] includes: `{% include "partial.html" %}` with depth limit
- [x] filters (phase 1): `escape`, `safe`, `default`, `upper`, `lower`, `length`
- [x] compatibility extensions: `{% set %}`, `{% for ... else %}`, operators (`and/or/not`, comparisons, `in/not in`, `is` tests)
- [x] compatibility extensions: extra filters (`join`, `trim`, `replace`, `capitalize`, `title`) and loop metadata (`length`, `revindex`, `revindex0`)
- [x] compatibility extensions: `raw/endraw`, whitespace control (`{{-`, `-}}`, `{%-`, `-%}`, `{#-`, `-#}`), and `for` unpack (`for k, v in ...`)
- [x] compatibility extensions: dict helpers (`items`, `keys`, `values`) for template iteration without function calls
- [x] TE-05: Context model and safety
- [x] primitives: `None`, `bool`, `int`, `float`, `str`, `bytes`
- [x] containers: `dict`, `list`, `tuple`
- [x] dotted lookup: `user.name` (dict/attr read-only)
- [x] strict mode toggle: undefined variable => error (default) or empty string
- [x] hard limits: max expression depth, max include depth, max loop iterations
- [x] TE-06: Performance architecture
- [x] compile cache in RAM/PSRAM with LRU + byte budget
- [x] invalidate by file mtime/size signature
- [x] static segment coalescing and constant folding
- [x] streaming renderer to avoid large intermediate buffers
- [x] optional precompile pass after boot (`template_warmup(root)`)
- [x] TE-07: Concurrency and locking
- [x] filesystem lock around file reads
- [x] template cache lock (coarse recursive mutex; read-mostly optimization pending)
- [x] no global mutable state in hot render path
- [x] TE-08: Integration with response pipeline
- [x] render path integrated into C response serialization
- [x] chunked/streaming compatibility
- [x] compatible with gzip/static/cache middleware behavior
- [x] TE-09: Error handling model
- [x] map template errors to HTTP 500 with short safe message
- [x] debug mode with source line preview (disabled by default)
- [x] TE-10: Security hardening
- [x] no function calls from templates (phase 1)
- [x] no arbitrary attribute write or object mutation
- [x] no path traversal in include resolution
- [x] TE-11: Tests
- [x] host parser/compiler unit tests (vectors: valid/invalid syntax)
- [x] host runtime tests (escaping, loops, includes, limits)
- [x] device E2E tests with real responses and concurrent requests
- [x] regression tests for memory leaks and cache invalidation
- [ ] TE-12: Benchmarks and acceptance gates
- [ ] compare `TemplateResponse` vs plain `Response` and static file
- [ ] throughput and p95 latency with cold cache and warm cache
- [ ] memory deltas (internal RAM and PSRAM)
- [ ] Acceptance: warm-cache render overhead <= 20% vs prebuilt static HTML for small pages
- [ ] Acceptance: no OOM/leak in 30 min sustained load
- [x] TE-13: Documentation and examples
- [x] template syntax guide
- [x] migration guide from string-concatenation handlers
- [x] best practices for partials/layouts and cache warmup
- [x] interactive template-based server UI (`/ui`) with endpoint matrix and quick HTTP/WS checks

### Template Engine rollout strategy
- [x] Milestone A (MVP): variables + `if` + `for` + escaping + `TemplateResponse`
- [x] Milestone B: includes + filter set + cache stats/clear APIs
- [ ] Milestone C: PSRAM-aware cache tuning + benchmark hardening + docs/examples
## 11. Benchmarking Plan

### NarzÄ™dzia
- **wrk** / **ab** (Apache Bench) z PC w sieci lokalnej
- **ESP-IDF task monitor** (runtime stats)
- **heap_caps_get_info()** (monitoring RAM)
- **SEGGER SystemView** (timing analysis)

### Scenariusze Testowe

| Test | Opis | Metryka |
|------|------|---------|
| Static small | Plik 1KB, keep-alive | req/s |
| Static large | Plik 100KB, gzip | MB/s throughput |
| JSON API (no deps) | GET, return dict | req/s, latency p50/p95/p99 |
| JSON API (with DI) | GET + 2x Depends chain | req/s, DI overhead |
| Python handler | Odczyt sensora + JSON | req/s, latency |
| WebSocket | Echo, 64-byte messages | msg/s, latency |
| Concurrent | 8 klientĂłw jednoczeĹ›nie | req/s, error rate |
| Long-running | 1h ciÄ…gĹ‚y ruch | stabilnoĹ›Ä‡, memory leaks |

### Cel wydajnoĹ›ciowy
- **Static files**: >500 req/s (1KB), >50 req/s (100KB)
- **JSON API (C-only)**: >200 req/s
- **JSON API (Python handler + DI)**: >40 req/s
- **WebSocket throughput**: >500 msg/s
- **Latency p95**: <50ms dla Python handlers, <5ms dla C-only
- **DI overhead**: <10ms per Depends chain (3 deep)
- **Memory**: <64KB overhead ponad czysty MicroPython

---

## 12. Podsumowanie Decyzji Architektonicznych

| Decyzja | WybĂłr | Uzasadnienie |
|---------|-------|--------------|
| API philosophy | **FastAPI-like** | Nowoczesne, DI-first, async-first, type-aware |
| Dual-core | TAK | Separacja I/O (C/Core 0) od logiki (Python/Core 1) |
| Serwer na Core 0 | TAK | WiFi driver jest na Core 0 |
| IPC mechanizm | FreeRTOS queues + ring buffer | Niski latency, zero-copy dla danych |
| HTTP parser | Custom zero-copy | Brak alokacji, pointer arithmetic |
| Router | Trie z typed params | O(n) od URI, auto-konwersja typĂłw |
| Kompresja | miniz | Lightweight (~10KB code), DEFLATE/gzip |
| Memory | Pool allocator | Zero malloc na hot path |
| MicroPython binding | C user module | Wkompilowany w firmware |
| Filesystem | VFS abstraction | FAT/LittleFS interchangeable |
| WebSocket keepalive | Auto w C | Nie angaĹĽuje Pythona |
| Static files | 100% C | Najszybsza Ĺ›cieĹĽka, zero IPC |
| Dependency Injection | Python-side Depends() | ElastycznoĹ›Ä‡, Ĺ‚atwoĹ›Ä‡ uĹĽycia, chain support |
| Error handling | HTTPException + handlers | SpĂłjne z FastAPI, czytelne komunikaty |
| Middleware | C-native + Python | Szybkie (CORS, gzip) + elastyczne (custom) |
| Auto-serialization | return dict â†’ JSON | Mniej boilerplate'u, czytelniejszy kod |

---

*Nazwa robocza: **ViperHTTP** â€” "FastAPI for Microcontrollers". Od "viper" (Python) i szybkoĹ›ci.*

---

## 13. Async Runtime Migration (Execution Tracker)

Status: in progress.

- [x] IPC safety hardening:
- [x] release ring payload on `send_response` queue push failure (`mod_viperhttp.c`)
- [x] response demux by `request_id` in server runtime (pending inbox + timeout waits)
- [x] safe cleanup for unmatched/overflowed IPC responses (no silent payload leaks)
- [x] concurrency step 1:
- [x] replace single accept->handle->close path with bounded accept queue + worker pool
- [x] atomic request id generation for concurrent workers
- [x] apply backpressure when accept queue is full (immediate 503)
- [x] WebSocket handoff to dedicated WS task (long-lived WS no longer blocks HTTP worker)
- [x] worker-pool bootstrap fallback: start with available workers under RAM pressure (no hard fail when full configured pool cannot be created)
- [x] FS/VFS lock contention reduction:
- [x] static file path now keeps FS lock around file syscalls, not around socket send path
- [ ] concurrency step 2 (target architecture):
- [x] stage A scaffolding for event-loop migration: feature flag `VHTTP_HTTP_EVENT_LOOP`, per-connection state registry/telemetry (`event_*` counters), compatibility accept->worker path retained
- [x] non-blocking socket I/O for HTTP path (`recv/send` readiness waits, bounded wait slices)
- [x] stage B beta runtime path: connection-slot event loop (`READ_REQ -> WAIT_IPC`) behind `VHTTP_HTTP_EVENT_LOOP`, keep-alive + static/ws handling without worker-per-connection dispatch
- [ ] full socket state-machine/event loop for read/write readiness (no blocking per worker)
- [x] stream-response path parity in event-loop mode (chunked/final handling in `WAIT_IPC` path, no 501 fallback)
- [x] central IPC response dispatcher task (workers no longer pop directly from `response_queue`)
- [x] response dispatcher integrated with multi-connection runtime loop
- [x] fairness scheduling for streaming/WebSocket under mixed traffic
- [ ] telemetry + stress gates:
- [x] runtime telemetry API: `viperhttp.server_stats()` + reset + `/debug/server-stats`
- [x] host stress tool: `tools/http_concurrency_test.py` with latency + counter dump
- [x] stress gate profiling split (`api`/`mixed`/`static`) + HTTP status distribution in `tools/http_stress_gate.py`
- [x] performance regression harness with persisted history + deltas (`tools/perf_regression.py`, `tools/perf_history/`) and reliability guards (lock, watchdog timeout, heartbeat, partial checkpoints, atomic writes)
- [x] server backpressure diagnostics in runtime stats (`ipc_req_ring_alloc_fail`, `ipc_req_queue_push_fail`, `backpressure_503_sent`)
- [x] app partitions expanded (16MiB layout) to increase firmware headroom while preserving large VFS
- [ ] p95/p99 latency under concurrent keep-alive load (device gate: `tools/http_stress_gate.py`, burst profile still requires tuning)
- [x] long-run leak/fragmentation checks (IPC ring + heap/PSRAM) via `/debug/memory-stats` deltas under stress
- [ ] final gate:
- [x] flash COM14 and run full device E2E (host_full_test + ws_test + manual curl sweep) after runtime refactors
- [x] resolve current COM14 E2E regression: `/file` If-Range mismatch/stale-date semantics and invalid-range status path (host_full_test)
- [x] mixed-load timeout/error regression mitigated (synthetic 12-client load no longer shows high timeout/error rate after adaptive keep-alive pressure tuning)
- [x] runtime tuning pass: pending-response lock retry, keep-alive pressure tuning, Wi-Fi power-save disabled in runner (`tools/run_server_wifi.py`)
- [x] event-loop `WAIT_IPC` drain budget + larger pending inbox (`VHTTP_EVENT_LOOP_WAIT_IPC_DRAIN_BUDGET`, `VHTTP_PENDING_RESP_SLOTS`) to prevent per-request stream backlog/drops
- [x] canceled-request IPC guard (`VHTTP_CANCELED_REQ_SLOTS`): drop late responses for aborted requests, release ring payloads, and recover from overload without hard reset
- [x] stability hotfix after COM14 panic under load: socket-fd validation guard + rollback worker stack (`8192 -> 12288`) to remove Core0 `select()` crash
- [x] dynamic worker autoscaling (start at `VHTTP_SERVER_MIN_WORKERS`, scale-up on accept queue pressure with cooldown/backoff)
- [x] PSRAM fallback for worker recv buffers (graceful fallback to internal RAM when PSRAM unavailable) + telemetry (`workers_recv_psram`, `workers_recv_ram`)
- [x] worker-stack/memory refactor for higher stable worker count (target: >7 workers without panic): warm-start retries + runtime worker limits API (`set_worker_limits`, `get_worker_limits`)
- [x] bridge dispatch tuning pass: bridge worker/queue knobs exposed in `viperhttp_bridge.run(...)` and stress harness retry hardened (`tools/http_stress_gate.py`)
- [x] heavy mixed profile no longer shows persistent IPC backpressure counters after tuning (`ipc_req_queue_push_fail=0`, `backpressure_503_sent=0` in current short gate runs)
- [ ] heavy `api`/`mixed` stress profiles still fail burst SLO on tail latency/error rate; current bottleneck is primarily MicroPython bridge/handler throughput (IPC backpressure counters stay near zero)
- [x] investigate/raise effective TCP socket ceiling: lifted via `CONFIG_VFS_MAX_COUNT=20` + lwIP limits (`MAX_SOCKETS/ACTIVE/LISTENING=20`, `TCP_RECVMBOX=16`, `TCPIP_RECVMBOX=64`)
- [x] low-latency socket option enabled in C runtime (`TCP_NODELAY` on accepted sockets) and validated with COM14 device E2E
- [x] event-loop stability fix: listen socket is non-blocking before burst-accept loop (prevents post-first-request stall)
- [x] async queue-pressure handling in event-loop: new deferred `WAIT_REQ_QUEUE` state retries IPC request enqueue without blocking or immediate 503
- [x] exact-file static mount API on C side: `app.mount_file(path, file)` for VFS-backed C static serving without Python handler dispatch
- [x] demo app routes `/file`, `/file-html`, `/file-missing` migrated to C static exact-file mounts (fallback to `FileResponse` only when `mount_file` unavailable)
- [x] request-path micro-optimization: `Request.query_params` parsed lazily on first access; avoid eager query-dict allocation in `poll_request`
- [x] bridge loop tuning extended: runtime knobs `bridge_poll_burst` + `bridge_idle_sleep_ms` added to `viperhttp_bridge.run(...)`
- [x] COM14 validation after changes: rebuild+flash+VFS sync, `host_full_test` PASS, `ws_test` PASS, `run_device_all_tests.ps1` PASS
- [x] streaming IPC throttling refactor: removed fixed `delay_ms(1)` from hot path and replaced with adaptive backpressure yield (queue/ring pressure thresholds)
- [x] IPC introspection helpers added for throttling decisions (`vhttp_ipc_queue_count/capacity`, `vhttp_ipc_ring_used`)
- [x] MicroPython bridge autoscaling implemented: dynamic bridge worker pool (`bridge_min_workers`, `bridge_max_workers`, `bridge_autoscale`) with queue-pressure scale-up and idle scale-down to min
- [x] bridge hot-path allocation reduction: background task container is now lazy-instantiated per request (no eager allocation when unused)
- [x] COM14 validation after bridge autoscale/hot-path update: `host_full_test` PASS, `ws_test` PASS, `run_device_all_tests.ps1` PASS, `http_stress_gate --profile api` PASS
- [x] bridge enqueue/runtime tuning pass v2: bounded enqueue wait + aggressive autoscale burst + worker cooperative-yield cadence (`bridge_enqueue_wait_ms`, `bridge_scale_up_max_burst`, `bridge_worker_yield_every`)
- [x] benchmark harness hardened and baseline refreshed with isolated profiles (`c_static_only`, `python_light`, `python_heavy`) + per-path metrics persisted in `tools/perf_history/`
- [ ] mixed-load bottleneck still present: effective throughput on MicroPython-dispatched routes is ~3.8-4.2 req/s (ok_rps) under current `api`/`mixed` stress profiles, depending on Python-route share
- [ ] post-throttling stress gate still fails latency SLO on device for `mixed` profile (`p95>2s`, `p99>3s`, occasional `504`), so next focus remains MicroPython bridge throughput and per-request Python overhead on Python-dispatched endpoints
- [x] experiment (2026-02-09): `VHTTP_IPC_RESPONSE_QUEUE_LEN=24` + `VHTTP_STATIC_STREAM_CHUNK_SIZE=8192` introduced static gzip timeout/regression under `/static/large.txt`; rolled back to `16` / `16384`
- [x] experiment (2026-02-09): bridge runtime tuning in `tools/run_server_wifi.py` (`bridge_max_workers=10`, `bridge_scale_up_max_burst=8`) increased mixed tail latency/error risk; rolled back to `8` / `6`
- [x] experiment (2026-02-09): `VHTTP_STATIC_STREAM_CHUNK_SIZE=32768` showed inconsistent mixed behavior (one run better tail, rerun severe `mixed:long` regression); rolled back to `16384`
- [x] experiment (2026-02-09): telemetry-only pass for stream IPC backpressure added to `viperhttp.server_stats()` (`mp_stream_backpressure_*` counters) and validated on COM14 (`host_full_test` PASS, `ws_test` PASS)
- [x] experiment (2026-02-09): increased `VHTTP_IPC_RINGBUF_SIZE_PSRAM` from `262144` to `393216`; under `api,mixed` perf runs IPC pressure counters dropped to zero (`ring_full=0`, `dropped_requests=0`, `backpressure_hits` near zero), with consistent `mixed:long` tail improvement vs `rollback_final`
- [x] experiment (2026-02-09): bridge warm-up tweak `BRIDGE_MIN_WORKERS=6` reduced some mixed burst errors but caused unstable tradeoff (`api:burst` error-rate spikes) and one startup retry (`response dispatcher init failed`); rolled back to `BRIDGE_MIN_WORKERS=4`
- [ ] remaining issue (2026-02-09): `mixed:burst` is still non-deterministic (transport timeout spikes without HTTP 5xx and without IPC pressure), so next focus is bridge accept/warmup behavior and host-side burst methodology calibration (multi-run median gate)
- [x] experiment (2026-02-09): established 3-run median baseline for `mixed` on COM14 with `ring=393216` (`perf_20260209T091346Z_mixed_baseline_ring393216_r3_20260209.*`): `mixed:burst err=3.70% p95=2216.64`, `mixed:long err=0.23% p95=1800.65`
- [x] experiment (2026-02-09): bridge loop warm-up knob `bridge_poll_burst=6` in `tools/run_server_wifi.py` regressed reliability/perf (`perf_20260209T091924Z_mixed_pollburst6_ring393216_r3_20260209.*`), with higher median error/tail and rising IPC `ring_full`; rolled back
- [x] experiment (2026-02-09): attempted larger IPC ring `VHTTP_IPC_RINGBUF_SIZE_PSRAM=524288` caused severe mixed-profile regression (`perf_20260209T093551Z_mixed_ring524288_r3_20260209.*`); rolled back to `393216`
- [x] rollback validation (2026-02-09): rebuilt/flashed COM14 back to `ring=393216`; functional gates pass (`host_full_test` PASS, `ws_test` PASS with occasional first-run WS timeout flake)
- [ ] current bottleneck (2026-02-09): `mixed:burst` remains burst-error dominated and highly variable run-to-run; no tested bridge/ring knob today improved both burst error-rate and tail latency simultaneously
- [x] HTTPS complete (2026-02-09): runtime toggle + cert/key API wired (`viperhttp.start`/`bridge.run`), TLS handshake integrated for worker+event-loop paths, TLS-aware WSS runtime wiring, COM14 device validation passed (`run_https_tests` incl. repeated WSS), and TLS profiling captured (`tools/https_profile.py`, `tools/https_profile.last.json`, `tools/https_profile_20260209.md`)
- [x] HTTP/2 stream-state baseline (2026-02-10): event-loop path now tracks per-stream RFC state transitions (`idle/open/half-closed(local|remote)/closed`), closes stream state on local/remote end + RST, and recycles closed stream-state slots; COM14 validation passed (`run_http2_tests.py` x10 `FAIL_COUNT=0`, `host_full_test.py` PASS, `ws_test.py` PASS, `run_device_all_tests.ps1` PASS)
- [x] HTTP/2 interleaving baseline (2026-02-10): event-loop path can accept one additional stream while previous stream waits on IPC response (buffered request dispatch), then continue sequentially without connection abort; added host regression `tools/http2_interleave_test.py` and wired into `tools/run_http2_tests.py`; COM14 validation passed (`run_http2_tests.py` x10 incl. interleave step `FAIL_COUNT=0`)
- [x] HTTP/2 interleaving queue v2 (2026-02-10): event-loop path now supports bounded queue of multiple buffered ready stream requests while one stream waits on IPC; added cleanup/RST handling for buffered entries and expanded host interleave regression to 3 streams on one connection; COM14 validation passed (`run_http2_tests.py` x10 incl. 3-stream interleave `FAIL_COUNT=0`, `host_full_test.py` PASS, `ws_test.py` PASS)
- [x] HTTP/2 interleaving DATA v3 (2026-02-10): event-loop path now supports switching active request context between streams while headers/body assembly is in progress (buffered per-stream request state), including strict `CONTINUATION` ordering guard; added `tools/http2_interleave_data_test.py` + `tools/http2_continuation_guard_test.py` and wired both into `tools/run_http2_tests.py`; COM14 validation passed (`run_http2_tests.py` x10 incl. new guard+DATA steps `FAIL_COUNT=0`, `host_full_test.py` PASS, `run_device_all_tests.ps1` PASS, `ws_test.py` latest 10/10 PASS after earlier intermittent timeout run)
- [x] HTTP/2 flow-control baseline v1 (2026-02-10): event-loop path now tracks connection/stream RX+TX windows, applies peer `SETTINGS_INITIAL_WINDOW_SIZE` to stream TX bookkeeping, validates invalid `WINDOW_UPDATE` (zero increment/overflow), and replenishes RX windows via `WINDOW_UPDATE` after DATA consume; added `tools/http2_window_update_validation_test.py` and wired into `tools/run_http2_tests.py`; COM14 validation passed (`run_http2_tests.py` x10 incl. WINDOW_UPDATE validation `FAIL_COUNT=0`, `host_full_test.py` PASS, `ws_test.py` PASS, `run_device_all_tests.ps1` PASS)
- [x] HTTP/2 h2c regression fix (2026-02-10): fixed event-loop h2c path where response could end after HEADERS without DATA/END_STREAM due missing TX stream slot during flow-control checks; TX bookkeeping now lazily rehydrates per-stream slot in `vhttp_http2_flow_tx_available` / `vhttp_http2_flow_consume_tx`. COM14 validation passed (`http2_request_test.py --upgrade-h2c` PASS, `run_http2_tests.py` PASS, `run_http2_tests.py` x10 `H2_FAIL_COUNT=0`, `host_full_test.py` PASS, `ws_test.py` PASS, `run_device_all_tests.ps1` PASS)

### 13.1 Stabilization Program (2026-02-09, COM14)

Objective:
- eliminate mixed-profile instability first, then optimize throughput without reintroducing regressions
- treat "0 errors" as target, but verify if residual failures are server-side or unavoidable Wi-Fi/client transport noise

Research snapshot (why this plan):
- `mixed:burst` variability is very high across runs (`err` median ~`4.9%`, range `0.63%..100%`; `p95` median ~`2260ms`)
- IPC pressure is no longer the primary limiter in recent runs (`ring_full/backpressure_503` near zero), but burst transport errors remain
- per-path medians show errors concentrated on short endpoints (`/hello`, sometimes `/api/ping`) rather than on heavy handlers, which suggests keep-alive churn/reconnect effects during burst pressure

#### Phase A - Observability hardening (must be done first)
- [ ] `tools/http_stress_gate.py`: classify and report transport exception types (`timeout`, `BrokenPipe`, `ConnectionReset`, `RemoteDisconnected`) separately from HTTP status failures
- [ ] `tools/http_stress_gate.py`: add optional one-shot retry for transport exceptions on idempotent GET to distinguish transient reconnect churn from true server failure
- [ ] `tools/http_stress_gate.py`: add per-connection lifecycle counters (`reconnects`, `requests_per_connection`) to quantify keep-alive churn
- [ ] `cmodules/viperhttp/viperhttp/core/vhttp_server.h` + `cmodules/viperhttp/viperhttp/core/vhttp_server_task.c` + `cmodules/viperhttp/viperhttp/mod_viperhttp.c`: expose close-reason counters (`close_idle_timeout`, `close_keepalive_pressure`, `close_ipc_timeout`, `close_parse_error`) in `server_stats`
- [ ] `viperhttp_bridge.py`: add bridge telemetry counters (`enqueue_retry_count`, `enqueue_drop_count`, `scale_attempts`, `scale_failures`, `worker_task_exceptions`) and surface via debug stats endpoint

Phase A acceptance:
- 3-run `mixed` can attribute >=95% of non-2xx/transport failures to explicit categories (no "unknown error bucket")

#### Phase B - Measurement protocol calibration (stop false positives)
- [ ] `tools/perf_regression.py`: enforce >=5 runs for `mixed` when evaluating bridge/runtime tuning, keep median-based aggregation, and track worst-run guardrail
- [ ] `tools/perf_regression.py`: add per-profile pass criteria split for `http_status_error_rate` vs `transport_error_rate`
- [ ] add two mixed variants:
- [ ] `mixed_keepalive` (current behavior)
- [ ] `mixed_short_conn` (`Connection: close`) to isolate keep-alive reuse artifacts
- [ ] document gate decision rule:
- [ ] "stable pass" requires median pass + no catastrophic run (`err > 10%` or `p95 > 4000ms`) in the sample set

Phase B acceptance:
- regression report clearly shows whether failures come from keep-alive transport churn or server 5xx/IPC paths

#### Phase C - Bridge-side stability fixes (MicroPython hot path)
- [ ] `viperhttp_bridge.py`: replace aggressive enqueue retry loop with deadline + adaptive backoff tied to queue depth (avoid synchronized retry storms)
- [ ] `viperhttp_bridge.py`: add autoscale hysteresis (`scale_up` and `scale_down` windows) so worker count does not oscillate under bursty load
- [ ] `viperhttp_bridge.py`: protect startup warm-up with readiness barrier (bridge starts polling only after min workers are actually alive)
- [ ] `tools/run_server_wifi.py`: test lower bridge worker ceilings (`max=6`, then `max=5`) with new hysteresis logic; keep configuration that minimizes error variance, not only best single-run p95

Phase C acceptance:
- on COM14, 5-run `mixed` median `transport_error_rate <= 1.0%`, `p95 <= 2200ms`, and worst-run `error_rate < 5%`

#### Phase D - C event-loop fairness and connection-lifecycle tuning
- [ ] `cmodules/viperhttp/viperhttp/core/vhttp_server_task.c`: make keep-alive pressure-closing policy tunable (threshold + cooldown), then test less aggressive turnover under burst
- [ ] `cmodules/viperhttp/viperhttp/core/vhttp_config.h`: add compile-time knobs for event-loop fairness (`accept budget`, wait slices, IPC drain budget) with explicit experiment matrix
- [ ] `cmodules/viperhttp/viperhttp/core/vhttp_server_task.c`: ensure close-path consistency and explicit close reason accounting on every forced close branch

Phase D acceptance:
- 5-run `mixed` worst-run no longer shows burst collapse pattern (no spikes similar to `8-10%` median error runs)

#### Phase E - Reliability proof and feasibility check for "error=0"
- [ ] run 10-run COM14 campaign (`api,mixed`) with fixed best config, persist in `tools/perf_history/` with timestamped artifact and delta markdown
- [ ] run functional gates after each candidate (`host_full_test`, `ws_test`, `run_device_all_tests.ps1`) to catch protocol regressions
- [ ] if residual non-zero errors remain, prove origin using Phase A counters:
- [ ] if server-side counters rise -> continue server fixes
- [ ] if only transport reconnect noise remains and server counters stay clean -> declare hardware/network floor with evidence

Final acceptance:
- target: `mixed` median error `0.0%`, `p95 < 2000ms`, `p99 < 3000ms`
- fallback success condition (resource-limited proof): no server-side failure counters + transport-only residuals bounded and reproducible across 10 runs


