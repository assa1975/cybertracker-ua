# API Документація CyberTracker UA

Повна специфікація REST API системи моніторингу кібератак.

**Базовий URL:** `http://127.0.0.1:5000`

---

## Зміст

- [Інциденти API](#інциденти-api)
- [IOC індикатори API](#ioc-індикатори-api)
- [Документи API](#документи-api)
- [Персони API](#персони-api)
- [Графові API](#графові-api)
- [Управління API](#управління-api)
- [Коди помилок](#коди-помилок)

---

## Інциденти API

### GET /api/incidents

Отримати список кіберінцидентів.

**Параметри запиту:**

| Параметр | Тип | За замовчуванням | Обов'язковий | Опис |
|----------|-----|------------------|--------------|------|
| q | string | - | Ні | Повнотекстовий пошук (заголовок, опис) |
| attack_type | string | - | Ні | Фільтр за типом атаки |
| severity | string | - | Ні | Фільтр за критичністю |
| source | string | - | Ні | Фільтр за джерелом |
| limit | integer | 50 | Ні | Кількість записів (макс. 100) |
| offset | integer | 0 | Ні | Зміщення для пагінації |

**Допустимі значення фільтрів:**

- `attack_type`: Phishing, Malware, Ransomware, Wiper, DDoS, Exploit, Espionage, Defacement, Supply Chain
- `severity`: Критичний, Високий, Середній, Низький
- `source`: CERT-UA, BleepingComputer, The Record, SecurityWeek, The Hacker News, Recorded Future, Google TAG, Microsoft Security, CISA, Cisco Talos, Mandiant

**Приклад запиту:**

```bash
curl "http://127.0.0.1:5000/api/incidents?q=phishing&severity=Критичний&limit=10"
```

**Приклад відповіді (200 OK):**

```json
{
  "total": 42,
  "incidents": [
    {
      "id": 1,
      "title": "New phishing campaign targets Ukrainian government",
      "title_uk": "Нова фішингова кампанія спрямована на уряд України",
      "description": "A sophisticated phishing attack...",
      "description_uk": "Витончена фішингова атака...",
      "date": "2026-02-14T10:30:00",
      "source": "The Record",
      "source_url": "https://therecord.media/example",
      "attack_type": "Phishing",
      "target_sector": "Уряд",
      "severity": "Критичний",
      "threat_actor": "APT28 (Fancy Bear)",
      "mitre_technique_id": "T1566.001",
      "ioc_indicators": "{\"ipv4\": [\"192.0.2.1\"], \"domains\": [\"evil.example.com\"]}",
      "created_at": "2026-02-14T11:00:00"
    }
  ]
}
```

---

## IOC індикатори API

### GET /api/ioc

Отримати список IOC (Indicators of Compromise) з фідів.

**Параметри запиту:**

| Параметр | Тип | За замовчуванням | Обов'язковий | Опис |
|----------|-----|------------------|--------------|------|
| q | string | - | Ні | Пошук по значенню IOC або опису |
| ioc_type | string | - | Ні | Фільтр за типом IOC |
| source | string | - | Ні | Фільтр за джерелом фіду |
| threat_level | string | - | Ні | Фільтр за рівнем загрози |
| limit | integer | 50 | Ні | Кількість записів (макс. 200) |
| offset | integer | 0 | Ні | Зміщення для пагінації |

**Допустимі значення:**

- `ioc_type`: ipv4, ipv6, domain, url, hash_md5, hash_sha1, hash_sha256, email, cve
- `threat_level`: critical, high, medium, low, unknown
- `source`: ThreatFox, URLhaus, Feodo Tracker, document_analysis, incident_extraction

**Приклад запиту:**

```bash
curl "http://127.0.0.1:5000/api/ioc?ioc_type=ipv4&threat_level=critical&limit=20"
```

**Приклад відповіді (200 OK):**

```json
{
  "total": 156,
  "indicators": [
    {
      "id": 1,
      "value": "203.0.113.42",
      "ioc_type": "ipv4",
      "source": "ThreatFox",
      "first_seen": "2026-02-10T08:00:00",
      "last_seen": "2026-02-14T16:30:00",
      "threat_level": "critical",
      "tags": "botnet,c2,cobalt-strike",
      "confidence": 95,
      "description": "Cobalt Strike C2 server",
      "enrichment_data": "{\"virustotal\": {\"malicious\": 45}, \"abuseipdb\": {\"score\": 100}}"
    }
  ]
}
```

---

## Документи API

### GET /api/documents

Отримати список завантажених та проаналізованих документів.

**Параметри запиту:**

| Параметр | Тип | За замовчуванням | Обов'язковий | Опис |
|----------|-----|------------------|--------------|------|
| q | string | - | Ні | Пошук по назві файлу |
| limit | integer | 50 | Ні | Кількість записів (макс. 100) |
| offset | integer | 0 | Ні | Зміщення для пагінації |

**Приклад запиту:**

```bash
curl "http://127.0.0.1:5000/api/documents?q=cert&limit=10"
```

**Приклад відповіді (200 OK):**

```json
{
  "total": 5,
  "documents": [
    {
      "id": 1,
      "original_name": "cert_ua_alert_2026.pdf",
      "doc_type": "pdf",
      "file_size": 245760,
      "page_count": 12,
      "language": "uk",
      "ioc_count": 15,
      "threat_actors": "APT28 (Fancy Bear), Gamaredon (Armageddon)",
      "attack_types": "Phishing, Malware",
      "target_sectors": "Уряд, Оборона",
      "mitre_techniques": "T1566, T1059, T1071",
      "summary": "Документ описує фішингову кампанію...",
      "created_at": "2026-02-13T14:20:00"
    }
  ]
}
```

### POST /documents/upload

Завантажити документ для аналізу.

**Content-Type:** `multipart/form-data`

**Параметри форми:**

| Параметр | Тип | Обов'язковий | Опис |
|----------|-----|--------------|------|
| file | File | Так | PDF, TXT, CSV або DOCX файл (макс. 50 MB) |

**Приклад запиту:**

```bash
curl -X POST -F "file=@document.pdf" http://127.0.0.1:5000/documents/upload
```

**Відповідь:** Redirect на `/documents/<id>` (302)

---

## Персони API

### GET /api/persons/search

Пошук загрозливих осіб.

**Параметри запиту:**

| Параметр | Тип | Обов'язковий | Опис |
|----------|-----|--------------|------|
| q | string | Так (мін. 1 символ) | Пошуковий запит (ім'я, псевдонім) |

**Приклад запиту:**

```bash
curl "http://127.0.0.1:5000/api/persons/search?q=ivan"
```

**Приклад відповіді (200 OK):**

```json
{
  "results": [
    {
      "id": 1,
      "name": "Ivanov Ivan Sergeevich",
      "aliases": "CyberBear",
      "role": "Hacker",
      "organization": "GRU Unit 26165",
      "country": "Russia"
    }
  ]
}
```

---

## Графові API

Всі графові ендпоінти мають префікс `/api/graph/`.

### GET /api/graph/status

Перевірка доступності Neo4j.

```bash
curl http://127.0.0.1:5000/api/graph/status
```

```json
{
  "available": true,
  "message": "Neo4j is connected"
}
```

### GET /api/graph/stats

Статистика графової бази.

```json
{
  "nodes": {
    "Incident": 45,
    "ThreatActor": 12,
    "AttackType": 9,
    "Sector": 9,
    "IOCIndicator": 234,
    "Person": 16,
    "Organization": 8,
    "Document": 5,
    "Source": 11,
    "MITRETechnique": 15,
    "Country": 3,
    "Operation": 7
  },
  "relationships": 856,
  "top_actors": [
    {"name": "APT28 (Fancy Bear)", "incidents": 12},
    {"name": "Sandworm (APT44)", "incidents": 8}
  ],
  "top_sectors": [
    {"name": "Уряд", "count": 18},
    {"name": "Енергетика", "count": 11}
  ]
}
```

### GET /api/graph/data

Отримати дані графу у форматі Cytoscape.js.

**Параметри запиту:**

| Параметр | Тип | За замовчуванням | Опис |
|----------|-----|------------------|------|
| actor | string | - | Фільтр за загрозливим актором |
| sector | string | - | Фільтр за сектором |
| attack_type | string | - | Фільтр за типом атаки |
| limit | integer | 500 | Макс. вузлів (макс. 2000) |

```bash
curl "http://127.0.0.1:5000/api/graph/data?actor=APT28&limit=100"
```

```json
{
  "nodes": [
    {
      "data": {
        "id": "incident_1",
        "label": "Phishing attack on...",
        "type": "Incident",
        "severity": "Критичний"
      }
    },
    {
      "data": {
        "id": "actor_apt28",
        "label": "APT28 (Fancy Bear)",
        "type": "ThreatActor"
      }
    }
  ],
  "edges": [
    {
      "data": {
        "source": "actor_apt28",
        "target": "incident_1",
        "label": "ATTRIBUTED_TO"
      }
    }
  ]
}
```

### GET /api/graph/centrality

Метрики центральності вузлів.

| Параметр | Тип | За замовчуванням | Опис |
|----------|-----|------------------|------|
| metric | string | degree | degree, betweenness, closeness, pagerank |
| limit | integer | 50 | Кількість топ-вузлів |

```bash
curl "http://127.0.0.1:5000/api/graph/centrality?metric=pagerank&limit=10"
```

```json
{
  "metric": "pagerank",
  "results": [
    {"node": "APT28 (Fancy Bear)", "type": "ThreatActor", "score": 0.0842},
    {"node": "Уряд", "type": "Sector", "score": 0.0651},
    {"node": "Sandworm (APT44)", "type": "ThreatActor", "score": 0.0534}
  ]
}
```

### GET /api/graph/communities

Виявлення спільнот (Louvain algorithm).

```json
{
  "communities": [
    {
      "id": 0,
      "size": 15,
      "members": ["APT28", "Phishing", "Уряд", "T1566"]
    },
    {
      "id": 1,
      "size": 12,
      "members": ["Sandworm", "Wiper", "Енергетика", "T1486"]
    }
  ],
  "modularity": 0.45
}
```

### GET /api/graph/actor/\<name\>

Профіль загрозливого актора.

```bash
curl "http://127.0.0.1:5000/api/graph/actor/APT28"
```

```json
{
  "name": "APT28 (Fancy Bear)",
  "incidents_count": 12,
  "techniques": ["T1566", "T1059", "T1071"],
  "sectors": ["Уряд", "Оборона", "Медіа"],
  "attack_types": ["Phishing", "Espionage"],
  "iocs": ["192.0.2.1", "evil.example.com"]
}
```

### GET /api/graph/path

Знайти найкоротший шлях між вузлами.

| Параметр | Тип | Обов'язковий | Опис |
|----------|-----|--------------|------|
| source | string | Так | Початковий вузол (назва) |
| target | string | Так | Кінцевий вузол (назва) |

```bash
curl "http://127.0.0.1:5000/api/graph/path?source=APT28&target=Енергетика"
```

```json
{
  "path": ["APT28 (Fancy Bear)", "Incident #23", "Енергетика"],
  "length": 2,
  "relationships": ["ATTRIBUTED_TO", "TARGETS"]
}
```

### POST /api/graph/sync

Синхронізувати всі дані з SQLite у Neo4j.

```bash
curl -X POST http://127.0.0.1:5000/api/graph/sync
```

```json
{
  "status": "success",
  "incidents_synced": 5,
  "persons_synced": 16,
  "organizations_synced": 8,
  "documents_synced": 2,
  "ioc_feeds_synced": 150
}
```

---

## Управління API

Ці ендпоінти запускають фонові процеси та повертають redirect на головну сторінку.

| Ендпоінт | Метод | Опис |
|----------|-------|------|
| /fetch | GET | Завантажити RSS-канали |
| /scrape | GET | Скрапити повні тексти |
| /translate | GET | Перекласти інциденти |
| /report | GET | Згенерувати щоденний звіт |
| /fetch-ioc-feeds | GET | Оновити IOC фіди |
| /fetch-twitter | GET | Завантажити з Twitter |
| /fetch-linkedin | GET | Завантажити з LinkedIn |
| /enrich | GET | Збагатити IOC (VT/AIPDB) |
| /import-threat-intel | GET | Імпортувати персони/організації |
| /sync-all-graph | GET | Синхронізувати все в Neo4j |
| /documents/\<id\>/sync-graph | GET | Синхронізувати документ в Neo4j |

---

## Коди помилок

| Код | Опис |
|-----|------|
| 200 | Успішний запит |
| 302 | Redirect після дії (нормально для управління) |
| 400 | Невірні параметри запиту |
| 404 | Ресурс не знайдений |
| 413 | Файл завеликий (> 50 MB) |
| 500 | Внутрішня помилка сервера |

---

*API Документація CyberTracker UA*
