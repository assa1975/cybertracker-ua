# CyberTracker UA

**Система моніторингу та аналізу кібератак проти України**

Повнофункціональна платформа для автоматичного збору, класифікації, аналізу та візуалізації кіберінцидентів, спрямованих проти України. Включає графову базу даних Neo4j, аналіз PDF-документів, IOC-індикатори та розвідку загроз.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-green?logo=flask&logoColor=white)
![Neo4j](https://img.shields.io/badge/Neo4j-5.20+-008CC1?logo=neo4j&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

---

## Зміст

- [Опис проекту](#опис-проекту)
- [Основні можливості](#основні-можливості)
- [Архітектура системи](#архітектура-системи)
- [Швидкий старт](#швидкий-старт)
- [Конфігурація](#конфігурація)
- [Модулі системи](#модулі-системи)
- [База даних](#база-даних)
- [Neo4j графова база](#neo4j-графова-база)
- [API документація](#api-документація)
- [Веб-інтерфейс](#веб-інтерфейс)
- [Структура проекту](#структура-проекту)
- [Технології](#технології)
- [Додаткова документація](#додаткова-документація)

---

## Опис проекту

CyberTracker UA - це комплексна система моніторингу кіберзагроз, спеціалізована на відстеженні кібератак проти України. Система автоматично:

1. **Збирає** дані з 11 RSS-каналів, Twitter/X, LinkedIn, IOC-фідів та PDF-документів
2. **Класифікує** інциденти за типом атаки, сектором, загрозливими акторами та рівнем критичності
3. **Екстрагує** IOC-індикатори (IP, домени, хеші, CVE, MITRE ATT&CK)
4. **Аналізує** звязки між акторами, інцидентами та індикаторами у графовій базі Neo4j
5. **Візуалізує** дані через інтерактивний графовий інтерфейс (Cytoscape.js)
6. **Генерує** звіти у форматі Word (.docx) з українською локалізацією

### Конвеєр обробки даних

```
                    +-----------------+
                    |  Джерела даних  |
                    +-----------------+
                           |
        +------------------+------------------+------------------+
        |                  |                  |                  |
   +---------+      +----------+       +----------+      +-----------+
   |11 RSS   |      |Twitter/X |       |IOC Feeds |      |PDF Upload |
   |каналів  |      |LinkedIn  |       |ThreatFox |      |TXT/CSV    |
   +---------+      +----------+       |URLhaus   |      +-----------+
        |                  |           |Feodo     |           |
        +------------------+------------------+---------------+
                           |
                    +------v------+
                    | Фільтрація  |
                    |  Україна    |
                    +------+------+
                           |
              +------------+------------+
              |                         |
       +------v------+          +------v-------+
       | Класифікація|          |IOC екстракція|
       | - Тип атаки |          | - IPv4/IPv6  |
       | - Сектор    |          | - Домени     |
       | - Актор     |          | - Хеші       |
       | - Severity  |          | - CVE, MITRE |
       +------+------+          +------+-------+
              +------------+------------+
                           |
                    +------v------+
                    |  SQLite DB  |
                    | 6 таблиць   |
                    +------+------+
                           |
           +---------------+---------------+
           |               |               |
    +------v------+ +------v------+ +------v------+
    |  Скрапінг   | |  Переклад   | | Збагачення  |
    |повних текстів| |  укр. мовою | | VirusTotal  |
    |+ зображення | |  (Google)   | | AbuseIPDB   |
    +------+------+ +------+------+ +------+------+
           +---------------+---------------+
                           |
                    +------v------+
                    |   Neo4j     |
                    | Графова БД  |
                    | 12 типів    |
                    | вузлів      |
                    +------+------+
                           |
              +------------+------------+
              |            |            |
       +------v---+ +-----v------+ +---v--------+
       |Граф аналіз| |Візуалізація| |Звіти .docx |
       |NetworkX  | |Cytoscape.js| |Щоденні     |
       |Centrality| |Інтерактив. | |Організації |
       |Community | |фільтри    | |IOC звіти   |
       +----------+ +------------+ +------------+
```

---

## Основні можливості

### 1. Збір даних з множинних джерел

| Джерело | Кількість | Інтервал | Опис |
|---------|-----------|----------|------|
| RSS-канали | 11 | 30 хв | CERT-UA, BleepingComputer, The Record, SecurityWeek, The Hacker News, Recorded Future, Google TAG, Microsoft Security, CISA, Cisco Talos, Mandiant |
| Twitter/X | 8 акаунтів | 15 хв | Потребує TWITTER_BEARER_TOKEN |
| LinkedIn | 6 запитів | 120 хв | Потребує GOOGLE_CSE_API_KEY |
| IOC фіди | 3 джерела | 60 хв | ThreatFox, URLhaus, Feodo Tracker |
| Документи | Без обмежень | Ручний | PDF, TXT, CSV, DOCX |

### 2. Автоматична класифікація

- **9 типів атак**: Phishing, Malware, Ransomware, Wiper, DDoS, Exploit, Espionage, Defacement, Supply Chain
- **9 цільових секторів**: Уряд, Енергетика, Оборона, Фінанси, Телеком, Освіта, Медицина, Інфраструктура, Медіа
- **10+ загрозливих акторів**: UAC-0001..0006, APT28/Fancy Bear, Sandworm/APT44, Gamaredon/Armageddon, Turla
- **4 рівні критичності**: Критичний, Високий, Середній, Низький
- **33 MITRE ATT&CK техніки**
- **3-рівнева дедуплікація**: URL uniqueness, URL normalization, fuzzy title match (>85%)

### 3. IOC екстракція та аналіз

Автоматичне розпізнавання з тексту:
- **IPv4/IPv6** адреси (включаючи defanged: `192[.]168[.]1[.]1`)
- **Домени** (включаючи defanged: `example[.]com`)
- **URL** (включаючи `hxxp://`, `hxxps://`)
- **Хеші**: MD5, SHA1, SHA256
- **CVE** ідентифікатори (CVE-YYYY-NNNNN)
- **Email** адреси
- **MITRE ATT&CK** техніки (T1234, T1234.001)

Фільтрація хибних спрацювань: приватні IP, загальні домени (40+), тривіальні хеші.

### 4. Аналіз PDF-документів

- Витяг тексту з PDF (PyMuPDF / PyPDF2 fallback)
- Підтримка TXT, CSV, DOCX форматів
- Автоматичне визначення мови (UK/EN/RU)
- Виявлення 30+ відомих загрозливих акторів
- Класифікація типів атак та секторів
- Екстракція MITRE ATT&CK технік
- Аналіз частоти ключових слів з бустом кіберсек-термінів
- Автоматична генерація підсумку

### 5. Графова аналітика (Neo4j)

- **12 типів вузлів**: Incident, ThreatActor, AttackType, Sector, MITRETechnique, IOCIndicator, Source, Person, Organization, Document, Country, Operation
- **18+ типів звязків**: ATTRIBUTED_TO, TARGETS, USES, CONTAINS, MEMBER_OF тощо
- **NetworkX аналіз**: Degree/Betweenness/Closeness/PageRank centrality
- **Виявлення спільнот** (Louvain algorithm)
- **Пошук найкоротших шляхів** між вузлами
- **Перехресний аналіз** між різними типами даних

### 6. Генерація звітів

- **Щоденні звіти** - автоматично о 08:00 UTC
- **Звіти по організаціях** - аналіз конкретної загрозливої групи
- **IOC звіти** - з фільтрацією за типом/рівнем загрози/джерелом
- Оформлення в кольорах українського прапора (синій #005BBB, жовтий #FFD500)

### 7. Веб-інтерфейс

- Інтерактивний дашборд з 4 графіками (Chart.js)
- Список інцидентів з 7 фільтрами та пагінацією
- Графова візуалізація (Cytoscape.js) з фільтрами та підсвіткою
- Директорія загрозливих осіб та організацій
- Каталог IOC-індикаторів зі збагаченням
- Перегляд завантажених документів з результатами аналізу

---

## Архітектура системи

```
+=====================================================================+
|                      WEB UI (Flask + Bootstrap 5)                    |
|  +--------+ +--------+ +------+ +----+ +----+ +-----+ +----------+ |
|  |Дашборд | |Інцидент| |Особи | |Орг.| |IOC | |Доки | |   Граф   | |
|  |графіки | | список | |каталог| |кат.| |фіди| |PDF  | |Cytoscape | |
|  +--------+ +--------+ +------+ +----+ +----+ +-----+ +----------+ |
+====================+======================+=========================+
                     |                      |
        +============v========+    +========v=============+
        |   Flask Routes      |    |   Graph API Routes   |
        | 30+ web endpoints   |    | /api/graph/*         |
        | /api/* JSON APIs    |    | stats, data, paths   |
        +=========+===========+    | centrality, sync     |
                  |                +=========+============+
                  |                          |
+=================v==========================v========================+
|                        BUSINESS LOGIC                               |
|  +----------+ +-------+ +----------+ +-----------+ +-------------+ |
|  |RSS Parser| |Scraper| |Translator| |PDF Analyzer| |IOC Feeds   | |
|  |11 feeds  | |BsSoup4| |Google TR | |IOC Extract | |ThreatFox   | |
|  |Classify  | |Images | |Chunk 4K  | |Actors,MITRE| |URLhaus     | |
|  +-----+----+ +---+---+ +----+-----+ +-----+-----+ |Feodo       | |
|        |           |          |             |        +------+------+ |
|  +-----+---+ +----+----------+----+ +------+------+ +------+------+|
|  |Twitter/X| |IOC Extractor      | |IOC Enrichment| |Threat Intel ||
|  |LinkedIn | |Regex, Defang, FP  | |VirusTotal    | |Persons,Orgs||
|  +---------+ +--------------------+ |AbuseIPDB     | +-------------+|
|                                     +--------------+                |
+=================================+=================================+
                                  |
              +-------------------+-------------------+
              |                                       |
   +----------v-----------+             +-------------v-----------+
   |     SQLite DB        |   sync_all  |     Neo4j Graph DB      |
   |  6 таблиць:          +------------>|  12 типів вузлів        |
   |  - incidents         |             |  18+ типів звязків      |
   |  - threat_persons    |             |  NetworkX аналіз:       |
   |  - threat_orgs       |             |  centrality, community  |
   |  - ioc_indicators    |             |  shortest paths         |
   |  - uploaded_documents|             |                         |
   |  - fetch_log         |             |                         |
   +----------------------+             +-------------------------+
```

Детальна архітектура: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Швидкий старт

### Системні вимоги

| Компонент | Мінімум | Рекомендовано |
|-----------|---------|---------------|
| Python | 3.10+ | 3.12+ |
| RAM | 2 GB | 4 GB |
| Диск | 500 MB | 2 GB |
| Neo4j | 5.20+ (опціонально) | 5.20+ |
| ОС | Windows 10 / Linux / macOS | - |

### Встановлення

```bash
# 1. Клонувати репозиторій
git clone https://github.com/your-repo/cybertracker-ua.git
cd cybertracker-ua

# 2. Створити віртуальне середовище
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Встановити залежності
pip install -r requirements.txt

# 4. Додаткові залежності для PDF-аналізу
pip install PyMuPDF PyPDF2 reportlab

# 5. Налаштувати змінні середовища
copy .env.example .env   # Windows
# cp .env.example .env   # Linux/macOS
# Відредагуйте .env за потребою

# 6. Запустити додаток
python run.py
```

### Перший запуск

```
=== Cyber Tracker UA ===
http://127.0.0.1:5000

  RSS feeds: 11 configured
  Neo4j:     Connected / Disabled
  Twitter:   Disabled (set TWITTER_BEARER_TOKEN in .env)
  LinkedIn:  Disabled (set GOOGLE_CSE_API_KEY & GOOGLE_CSE_ID in .env)
  VirusTotal:Disabled (set VIRUSTOTAL_API_KEY in .env)
  AbuseIPDB: Disabled (set ABUSEIPDB_API_KEY in .env)

Press Ctrl+C to stop
```

**Рекомендований порядок дій:**

```
1. Оновити RSS  ->  2. Скрапити  ->  3. Перекласти  ->  4. IOC фіди
                                                              |
5. Завантажити PDF  ->  6. Синхр. Neo4j  ->  7. Аналіз графу  ->  8. Звіт
```

---

## Конфігурація

### Файл .env

```bash
# Neo4j Graph Database (опціонально)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password    # Залиште порожнім для вимкнення

# Twitter/X API (опціонально)
TWITTER_BEARER_TOKEN=

# VirusTotal (опціонально)
VIRUSTOTAL_API_KEY=

# AbuseIPDB (опціонально)
ABUSEIPDB_API_KEY=

# Google Custom Search для LinkedIn (опціонально)
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_ID=
```

### Параметри config.py

| Параметр | Значення | Опис |
|----------|----------|------|
| FETCH_INTERVAL_MINUTES | 30 | Інтервал оновлення RSS |
| IOC_FETCH_INTERVAL_MINUTES | 60 | Інтервал IOC фідів |
| INCIDENTS_PER_PAGE | 20 | Записів на сторінці |
| IOC_PER_PAGE | 30 | IOC на сторінці |
| DOCS_PER_PAGE | 20 | Документів на сторінці |
| MAX_UPLOAD_SIZE_MB | 50 | Макс. розмір файлу |
| ALLOWED_EXTENSIONS | pdf, txt, csv, docx | Дозволені формати |

Повна конфігурація: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## Модулі системи

### Збір даних

| Модуль | Файл | Опис |
|--------|------|------|
| RSS парсер | rss_parser.py | 11 каналів, фільтрація, класифікація, дедуплікація |
| Скрапер | scraper.py | Повні тексти, сайт-специфічні CSS-селектори, зображення |
| Перекладач | translator.py | Google Translate, чанкування ~4000 символів |
| Twitter | twitter_fetcher.py | 8 акаунтів, Tweepy API |
| LinkedIn | linkedin_fetcher.py | Google Custom Search |
| IOC фіди | ioc_feed_fetcher.py | ThreatFox, URLhaus, Feodo Tracker |

### Аналіз та обробка

| Модуль | Файл | Опис |
|--------|------|------|
| IOC екстрактор | ioc_extractor.py | Regex IOC, defang, фільтрація FP |
| IOC збагачення | ioc_enrichment.py | VirusTotal, AbuseIPDB |
| PDF аналізатор | pdf_analyzer.py | Документи: IOC, актори, MITRE, ключові слова |
| Threat Intel | threat_intel_parser.py | Імпорт осіб та організацій |
| MITRE | mitre_data.py | ATT&CK маппінг |

### Графова аналітика

| Модуль | Файл | Опис |
|--------|------|------|
| Neo4j драйвер | graph_db.py | Підключення, схема, CRUD |
| Синхронізація | graph_sync.py | Всі типи даних -> Neo4j |
| Аналіз | graph_analysis.py | NetworkX centrality, communities, paths |
| API | graph_routes.py | REST API графу |

### Інфраструктура

| Модуль | Файл | Опис |
|--------|------|------|
| Планувальник | scheduler.py | 5 фонових задач (APScheduler) |
| Звіти | report_generator.py | Word .docx (3 типи) |
| Точка входу | run.py | Ініціалізація та запуск |

---

## База даних

### Схема SQLite (6 таблиць)

```
+------------------+     +-------------------+     +---------------------+
|    incidents     |     |  threat_persons   |     |threat_organizations |
+------------------+     +-------------------+     +---------------------+
| id (PK)          |     | id (PK)           |     | id (PK)             |
| title            |     | name              |     | name                |
| description      |     | aliases           |     | org_type            |
| date             |     | role              |     | aliases             |
| source           |     | organization      |     | country             |
| source_url (UQ)  |     | country           |     | parent_org          |
| attack_type      |     | description       |     | description         |
| target_sector    |     | operations (JSON) |     | known_operations    |
| threat_actor     |     | status            |     | members_count       |
| ioc_indicators   |     | source_url        |     | source_url          |
| severity         |     | photo_url         |     | created_at          |
| mitre_technique_id|    | created_at        |     +---------------------+
| title_uk         |     +-------------------+
| description_uk   |
| full_text        |     +-------------------+     +---------------------+
| full_text_uk     |     |ioc_indicators_feed|     |uploaded_documents   |
| images (JSON)    |     +-------------------+     +---------------------+
| neo4j_synced     |     | id (PK)           |     | id (PK)             |
| created_at       |     | value             |     | filename            |
+------------------+     | ioc_type          |     | original_name       |
                         | source            |     | file_size           |
+------------------+     | first_seen        |     | page_count          |
|    fetch_log     |     | last_seen         |     | doc_type            |
+------------------+     | threat_level      |     | extracted_text      |
| id (PK)          |     | tags              |     | language            |
| feed_name        |     | confidence        |     | ioc_data (JSON)     |
| fetched_at       |     | description       |     | ioc_count           |
| entries_found    |     | enrichment_data   |     | threat_actors       |
| entries_added    |     | created_at        |     | attack_types        |
| status           |     +-------------------+     | target_sectors      |
| error_message    |                               | mitre_techniques    |
+------------------+                               | keywords (JSON)     |
                                                   | summary             |
                                                   | neo4j_synced        |
                                                   | created_at          |
                                                   +---------------------+
```

---

## Neo4j графова база

### 12 типів вузлів

| Тип | Ключ | Опис |
|-----|------|------|
| Incident | incident_id | Кіберінцидент |
| ThreatActor | name | APT-група |
| AttackType | name | Тип атаки |
| Sector | name | Цільовий сектор |
| MITRETechnique | technique_id | ATT&CK техніка |
| IOCIndicator | value | IOC індикатор |
| Source | name | Джерело даних |
| Person | name | Загрозлива особа |
| Organization | name | Загрозлива організація |
| Document | doc_id | Завантажений документ |
| Country | name | Країна |
| Operation | name | Кібероперація |

### 18+ типів звязків

```
Incident --FROM--> Source
Incident --HAS_TYPE--> AttackType
Incident --TARGETS--> Sector
Incident --USES--> MITRETechnique
Incident --CONTAINS--> IOCIndicator
ThreatActor --ATTRIBUTED_TO--> Incident
ThreatActor --TARGETS--> Sector
ThreatActor --USES--> MITRETechnique
IOCIndicator --LINKED_TO--> ThreatActor
Person --MEMBER_OF--> Organization
Person --PARTICIPATED_IN--> Operation
Person --KNOWN_AS--> ThreatActor
Organization --SUBORDINATE_TO--> Organization
Organization --ASSOCIATED_WITH--> ThreatActor
Organization --CONDUCTED--> Operation
Organization --BASED_IN--> Country
Document --MENTIONS--> ThreatActor
Document --DESCRIBES--> AttackType
Document --REFERENCES--> Sector
Document --CONTAINS--> IOCIndicator
```

Детальна графова схема: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## API документація

### Інциденти API

```http
GET /api/incidents?q=phishing&severity=Критичний&limit=10
```

| Параметр | Тип | Опис |
|----------|-----|------|
| q | string | Пошук по заголовку/опису |
| attack_type | string | Фільтр за типом атаки |
| severity | string | Фільтр за критичністю |
| source | string | Фільтр за джерелом |
| limit | int | Макс. записів (за замовч. 50, макс. 100) |
| offset | int | Зміщення для пагінації |

### IOC API

```http
GET /api/ioc?ioc_type=ipv4&threat_level=critical&limit=50
```

### Документи API

```http
GET /api/documents?q=cert&limit=50
```

### Графові API

| Ендпоінт | Метод | Опис |
|----------|-------|------|
| /api/graph/status | GET | Статус Neo4j |
| /api/graph/stats | GET | Статистика графу |
| /api/graph/data | GET | Cytoscape.js дані |
| /api/graph/centrality | GET | Centrality метрики |
| /api/graph/communities | GET | Louvain communities |
| /api/graph/actor/\<name\> | GET | Профіль актора |
| /api/graph/path | GET | Найкоротший шлях |
| /api/graph/sync | POST | Синхронізація |

Повна API документація: [docs/API.md](docs/API.md)

---

## Веб-інтерфейс

| Сторінка | URL | Опис |
|----------|-----|------|
| Дашборд | / | Статистика, 4 графіки, останні інциденти |
| Інциденти | /incidents | Список, пошук, 7 фільтрів |
| Деталі інциденту | /incidents/\<id\> | IOC, MITRE, зображення |
| Додати інцидент | /incidents/new | Ручне створення |
| Персони | /persons | Каталог загрозливих осіб |
| Організації | /organizations | Каталог організацій |
| IOC індикатори | /ioc | Каталог IOC |
| Документи | /documents | Завантаження та аналіз |
| Граф | /graph | Інтерактивна візуалізація |

### Кнопки управління

| Кнопка | Дія |
|--------|-----|
| Оновити RSS | Завантажити нові інциденти |
| Скрапити | Завантажити повні тексти |
| Перекласти | Перекласти українською |
| Звіт | Згенерувати Word-звіт |
| Завантажити IOC | Оновити IOC-фіди |
| Синхр. все в Neo4j | Синхронізація у граф |

Посібник користувача: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)

---

## Структура проекту

```
cybertracker-ua/
|-- run.py                       # Точка входу
|-- app.py                       # Flask-додаток, 30+ маршрутів
|-- config.py                    # Конфігурація
|-- models.py                    # SQLAlchemy моделі (6 таблиць)
|-- database.py                  # Ініціалізація БД
|
|-- rss_parser.py                # RSS (11 каналів)
|-- scraper.py                   # Скрапінг + зображення
|-- translator.py                # Google Translate
|-- twitter_fetcher.py           # Twitter/X
|-- linkedin_fetcher.py          # LinkedIn/CSE
|
|-- ioc_extractor.py             # IOC regex
|-- ioc_enrichment.py            # VirusTotal / AbuseIPDB
|-- ioc_feed_fetcher.py          # ThreatFox, URLhaus, Feodo
|
|-- pdf_analyzer.py              # PDF/TXT/CSV/DOCX аналіз
|-- threat_intel_parser.py       # Імпорт осіб/організацій
|-- mitre_data.py                # MITRE ATT&CK
|
|-- graph_db.py                  # Neo4j драйвер
|-- graph_sync.py                # SQLite -> Neo4j синхронізація
|-- graph_analysis.py            # NetworkX аналітика
|-- graph_routes.py              # Graph REST API
|
|-- report_generator.py          # Word звіти
|-- scheduler.py                 # APScheduler (5 задач)
|
|-- templates/ (14 файлів)       # Jinja2 HTML
|-- static/                      # CSS, JS, зображення
|-- data/                        # SQLite, uploads, images
|-- docs/                        # Документація
|-- requirements.txt
|-- .env / .env.example
```

---

## Технології

| Компонент | Технологія | Версія |
|-----------|------------|--------|
| Веб-фреймворк | Flask | 3.1.0 |
| ORM | SQLAlchemy | 2.0.36 |
| Реляційна БД | SQLite | вбудована |
| Графова БД | Neo4j | 5.20+ |
| Граф-аналіз | NetworkX | 3.4.2 |
| RSS | feedparser | 6.0.11 |
| Планувальник | APScheduler | 3.10.4 |
| HTTP | requests | 2.32.3 |
| Переклад | googletrans | 4.0.0rc1 |
| Word | python-docx | 1.1.2 |
| HTML-парсинг | BeautifulSoup4 | 4.12.3 |
| Twitter | Tweepy | 4.14.0 |
| PDF | PyMuPDF / PyPDF2 | - |
| Фронтенд | Bootstrap 5.3 | - |
| Графіки | Chart.js 4.4 | - |
| Графова віз. | Cytoscape.js 3.28 | - |

---

## Планувальник задач

| Задача | Інтервал | Умова |
|--------|----------|-------|
| RSS оновлення | 30 хв | Завжди |
| Twitter | 15 хв | TWITTER_BEARER_TOKEN |
| LinkedIn | 120 хв | GOOGLE_CSE_API_KEY |
| IOC фіди | 60 хв | Завжди |
| Щоденний звіт | 08:00 UTC | Завжди |

---

## Додаткова документація

| Документ | Опис |
|----------|------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Детальна архітектура зі схемами |
| [API.md](docs/API.md) | Повна специфікація REST API |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Посібник користувача |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Розгортання та конфігурація |

---

## Ліцензія

MIT License

---

*Розроблено для моніторингу та аналізу кіберзагроз проти України.*
