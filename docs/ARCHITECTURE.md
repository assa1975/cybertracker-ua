# Архітектура CyberTracker UA

Детальна документація архітектури системи моніторингу кібератак в Україні.

**Версія документа:** 1.0  
**Дата:** 15 лютого 2026  
**Мова реалізації:** Python 3.10+  
**Фреймворк:** Flask 3.1.0  
**Бази даних:** SQLite (primary) + Neo4j 5.x (graph analysis)

---

## Зміст

1. [Загальна архітектура](#загальна-архітектура)
2. [Рівнева модель системи](#рівнева-модель-системи)
3. [Компонентна діаграма](#компонентна-діаграма)
4. [Структура файлів проєкту](#структура-файлів-проєкту)
5. [Модель даних SQLite](#модель-даних-sqlite)
6. [Графова модель Neo4j](#графова-модель-neo4j)
7. [Потоки даних](#потоки-даних)
8. [Система збору даних](#система-збору-даних)
9. [Система обробки та збагачення](#система-обробки-та-збагачення)
10. [IOC конвеєр](#ioc-конвеєр)
11. [Графова аналітика](#графова-аналітика)
12. [Веб-інтерфейс та API](#веб-інтерфейс-та-api)
13. [Система планування задач](#система-планування-задач)
14. [Генератор звітів](#генератор-звітів)
15. [Конфігурація та безпека](#конфігурація-та-безпека)
16. [Обробка помилок та стійкість](#обробка-помилок-та-стійкість)
17. [Масштабування](#масштабування)
18. [Статистика коду](#статистика-коду)

---

## Загальна архітектура

CyberTracker UA побудований за класичною серверною MVC-архітектурою з додатковими шарами для збору розвідданих (intelligence collection), обробки IOC (indicators of compromise), графового аналізу звязків та автоматичної генерації звітів.

Система складається з пяти основних рівнів:

```
  +========================================================================+
  |                    ЗОВНІШНІ ДЖЕРЕЛА ДАНИХ                               |
  |  +--------+ +--------+ +--------+ +---------+ +---------+             |
  |  |CERT-UA | |Bleeping| |The     | |Hacker   | |Security |             |
  |  |RSS     | |Computer| |Record  | |News     | |Week     |             |
  |  +---+----+ +---+----+ +---+----+ +----+----+ +----+----+             |
  |  +---+----+ +---+----+ +--+-----+ +---+----+ +----+----+             |
  |  |Recorded| |Google  | |Microsft| |CISA    | |Cisco   |             |
  |  |Future  | |TAG     | |Security| |Alerts  | |Talos   |             |
  |  +---+----+ +---+----+ +---+----+ +---+----+ +---+----+             |
  |  +---+----+ +---+----+ +--+-----+                                    |
  |  |Mandiant| |Twitter | |LinkedIn|  (11 RSS + social + 3 IOC feeds)   |
  |  +---+----+ +---+----+ +---+----+                                    |
  |  +---+----+ +---+----+ +--+-----+                                    |
  |  |ThreatFox |URLhaus | |Feodo   |                                    |
  |  +---+----+ +---+----+ +---+----+                                    |
  +======|===========|===========|========================================+
         |           |           |
  +======v===========v===========v========================================+
  |                РІВЕНЬ ЗБОРУ ДАНИХ (Collection Layer)                   |
  |  rss_parser.py | twitter_fetcher.py | linkedin_fetcher.py             |
  |  ioc_feed_fetcher.py | threat_intel_parser.py                         |
  +===========|=======================================================+
              |
  +==========v========================================================+
  |            РІВЕНЬ ОБРОБКИ (Processing & Enrichment Layer)          |
  |  scraper.py | translator.py | ioc_extractor.py | pdf_analyzer.py  |
  |  ioc_enrichment.py | mitre_data.py                                |
  +===========|=======================================================+
              |
  +==========v========================================================+
  |            РІВЕНЬ ЗБЕРІГАННЯ (Data Storage Layer)                   |
  |  +---------------------+    +---------------------------+          |
  |  | SQLite (Primary)    |    | Neo4j (Graph Analysis)    |          |
  |  | 6 tables            |<-->| 12 node labels            |          |
  |  | SQLAlchemy 2.0 ORM  |sync| 18+ relationship types    |          |
  |  +---------------------+    +---------------------------+          |
  |  +---------------------+    +---------------------------+          |
  |  | File System         |    | API Caches                |          |
  |  | images/ uploads/    |    | MITRE ATT&CK JSON         |          |
  |  +---------------------+    +---------------------------+          |
  +===========|=======================================================+
              |
  +==========v========================================================+
  |            РІВЕНЬ ПРЕДСТАВЛЕННЯ (Presentation Layer)                |
  |  Flask app.py (35+ routes) | graph_routes.py (8 API endpoints)     |
  |  14 Jinja2 templates | Bootstrap 5 | Chart.js | Cytoscape.js       |
  +===========|=======================================================+
              |
  +==========v========================================================+
  |            РІВЕНЬ ПЛАНУВАННЯ (Scheduling Layer)                     |
  |  APScheduler 3.10: RSS(30m) Twitter(15m) LinkedIn(120m)            |
  |                    IOC(60m) DailyReport(08:00)                     |
  +====================================================================+
```

---

## Рівнева модель системи

| Рівень | Відповідальність | Ключові модулі |
|--------|-----------------|----------------|
| **Збір даних** | Отримання сирих даних із зовнішніх джерел | rss_parser.py, twitter_fetcher.py, linkedin_fetcher.py, ioc_feed_fetcher.py, threat_intel_parser.py |
| **Обробка** | Скрейпінг, переклад, екстракція IOC, аналіз PDF | scraper.py, translator.py, ioc_extractor.py, ioc_enrichment.py, pdf_analyzer.py, mitre_data.py |
| **Зберігання** | Персистентне зберігання та синхронізація | database.py, models.py, graph_db.py, graph_sync.py |
| **Аналітика** | Графовий аналіз, центральність, спільноти | graph_analysis.py |
| **Представлення** | Веб-інтерфейс, API, візуалізація | app.py, graph_routes.py, templates, static |
| **Планування** | Фонові задачі, генерація звітів | scheduler.py, report_generator.py |

---

## Структура файлів проєкту

```
proekt/
+-- run.py                      # Точка входу: init DB, scheduler, Flask
+-- app.py                      # Flask factory + 35+ routes (1048 рядків)
+-- config.py                   # Конфігурація: feeds, keywords, API (232)
+-- database.py                 # SQLAlchemy engine, session, migration (48)
+-- models.py                   # 6 ORM моделей + індекси (242)
|
+-- rss_parser.py               # RSS збір + класифікація + дедуплікація (311)
+-- twitter_fetcher.py          # Twitter API v2 via tweepy (267)
+-- linkedin_fetcher.py         # LinkedIn via Google CSE (270)
+-- ioc_feed_fetcher.py         # ThreatFox + URLhaus + Feodo (353)
+-- threat_intel_parser.py      # APT persons/organizations data (576)
|
+-- scraper.py                  # Скрейпінг статей + зображень (296)
+-- translator.py               # Переклад через googletrans (171)
+-- ioc_extractor.py            # Екстракція IOC з тексту (338)
+-- ioc_enrichment.py           # VT + AbuseIPDB збагачення (316)
+-- pdf_analyzer.py             # Аналіз PDF документів (611)
+-- mitre_data.py               # MITRE ATT&CK кеш (82)
|
+-- graph_db.py                 # Neo4j connection manager (168)
+-- graph_sync.py               # SQLite -> Neo4j синхронізація (735)
+-- graph_analysis.py           # NetworkX аналітика (295)
+-- graph_routes.py             # Graph API Blueprint (280)
|
+-- scheduler.py                # APScheduler: 5 фонових задач (183)
+-- report_generator.py         # DOCX звіти (586)
+-- requirements.txt            # 13 Python залежностей
|
+-- templates/                  # 14 Jinja2 HTML шаблонів (2305 рядків)
|   +-- base.html               #   Bootstrap 5 layout (131)
|   +-- dashboard.html          #   Chart.js графіки (158)
|   +-- incidents.html          #   Список з фільтрами (150)
|   +-- incident_detail.html    #   Деталі інциденту (166)
|   +-- incident_form.html      #   Форма створення (106)
|   +-- persons.html            #   Каталог осіб (216)
|   +-- person_detail.html      #   Профіль особи (138)
|   +-- organizations.html      #   Каталог організацій (85)
|   +-- organization_detail.html#   Профіль організації (156)
|   +-- ioc_list.html           #   IOC таблиця (199)
|   +-- ioc_detail.html         #   Деталі IOC (148)
|   +-- documents.html          #   Документи + upload (231)
|   +-- document_detail.html    #   Аналіз PDF (232)
|   +-- graph.html              #   Граф-візуалізація (189)
|
+-- static/
|   +-- css/style.css           #   Кастомні стилі (123)
|   +-- js/dashboard.js         #   Chart.js графіки (113)
|   +-- js/graph.js             #   Cytoscape.js (454)
|   +-- js/incidents.js         #   Фільтрація (11)
|   +-- images/logo.png         #   Логотип
|   +-- images/persons/         #   Фото осіб
|
+-- data/
    +-- cybertracker.db         #   SQLite база
    +-- attack_techniques.json  #   MITRE ATT&CK кеш
    +-- images/{id}/            #   Зображення статей
    +-- uploads/                #   PDF/TXT/CSV/DOCX
```

---

## Модель даних SQLite

### ER-діаграма

```
+========================+          +========================+
|      incidents         |          |    threat_persons      |
+========================+          +========================+
| PK id           INT    |          | PK id           INT    |
|    title        VARCHAR|          |    name         VARCHAR|
|    description  TEXT   |          |    aliases      VARCHAR|
|    date         DATETIME|         |    role         VARCHAR|
|    source       VARCHAR|          |    organization VARCHAR|
|    source_url   VARCHAR| UNIQUE   |    country      VARCHAR|
|    attack_type  VARCHAR|          |    description  TEXT   |
|    target_sector VARCHAR|         |    operations   TEXT   | (JSON)
|    threat_actor VARCHAR|          |    status       VARCHAR|
|    ioc_indicators TEXT | (JSON)   |    source_url   VARCHAR|
|    severity     VARCHAR|          |    photo_url    VARCHAR|
|    mitre_technique_id  |          |    created_at   DATETIME|
|              VARCHAR   |          +========================+
|    title_uk     VARCHAR|          | idx_person_name         |
|    description_uk TEXT |          | idx_person_org          |
|    full_text    TEXT   |          | idx_person_role         |
|    full_text_uk TEXT   |          +========================+
|    images       TEXT   | (JSON)
|    neo4j_synced DATETIME|         +========================+
|    created_at   DATETIME|         | threat_organizations   |
+========================+          +========================+
| idx_date               |          | PK id           INT    |
| idx_source             |          |    name         VARCHAR|
| idx_attack_type        |          |    org_type     VARCHAR|
| idx_severity           |          |    aliases      VARCHAR|
| idx_target_sector      |          |    country      VARCHAR|
+========================+          |    parent_org   VARCHAR| (self-ref)
                                    |    description  TEXT   |
                                    |    known_operations TEXT| (JSON)
+========================+          |    members_count INT   |
|  ioc_indicators_feed   |          |    source_url   VARCHAR|
+========================+          |    created_at   DATETIME|
| PK id           INT    |          +========================+
|    value        VARCHAR|          | idx_org_name            |
|    ioc_type     VARCHAR|          | idx_org_type            |
|    source       VARCHAR|          +========================+
|    first_seen   DATETIME|
|    last_seen    DATETIME|         +========================+
|    threat_level VARCHAR|          |  uploaded_documents    |
|    tags         VARCHAR|          +========================+
|    confidence   INT    |          | PK id           INT    |
|    description  TEXT   |          |    filename     VARCHAR|
|    enrichment_data TEXT| (JSON)   |    original_name VARCHAR|
|    created_at   DATETIME|         |    file_size    INT    |
+========================+          |    page_count   INT    |
| idx_ioc_value          |          |    doc_type     VARCHAR|
| idx_ioc_type           |          |    title        VARCHAR|
| idx_ioc_source         |          |    extracted_text TEXT |
| idx_ioc_threat_level   |          |    language     VARCHAR|
| idx_ioc_first_seen     |          |    ioc_data     TEXT   | (JSON)
+========================+          |    ioc_count    INT    |
                                    |    threat_actors VARCHAR|
+========================+          |    attack_types VARCHAR|
|      fetch_log         |          |    target_sectors VARCHAR|
+========================+          |    mitre_techniques VARCHAR|
| PK id           INT    |          |    keywords     TEXT   | (JSON)
|    feed_name    VARCHAR|          |    summary      TEXT   |
|    fetched_at   DATETIME|         |    neo4j_synced DATETIME|
|    entries_found INT   |          |    created_at   DATETIME|
|    entries_added INT   |          +========================+
|    status       VARCHAR|          | idx_doc_filename       |
|    error_message TEXT  |          | idx_doc_type           |
+========================+          | idx_doc_created        |
                                    +========================+
```

### Стратегія дедуплікації (3 рівні)

```
Рівень 1: source_url UNIQUE constraint -> IntegrityError при дублі
         |
Рівень 2: URL нормалізація (видалення utm_source, utm_medium, utm_campaign, ref)
         |
Рівень 3: SequenceMatcher(title1, title2).ratio() > 0.85 -> дублікат
         (порівняння з останніми 200 заголовками)
```

---

## Графова модель Neo4j

### Діаграма вузлів та звязків

```
                                +============+
                                |   Source    |
                                |   name     |
                                +======+=====+
                                   ^   ^
                             FROM /     \ FROM
                                 /       \
                      +==========+==+ +=+============+
                      |  Incident   | | IOCIndicator |
                      | incident_id | | value        |
                      | title       | | type         |
                      | date        | | threat_level |
                      | severity    | +==+====+=+====+
                      +=+==+==+=+===+    |    | |
                        |  |  | |   CONT-|    | |LINKED_TO
                        |  |  | |   AINS |    | |
               HAS_TYPE |  |  | |        |    | |
                        v  |  | v        v    | |
               +========+  |  | +====+  |    | |  +==========+
               |AttackType| |  |Sector|  |    | |  | Country  |
               | name     | |  | name |  |    | |  | name     |
               +=+========+ |  +======+  |    | |  +=====+====+
                 ^          |   ^        |    | |        ^
            DESC-|     ATTR-|   |TARGETS |    | |   BASED_IN
            RIBES|     IBUTED|  |        |    | |        |
                 |     _TO  |   |        |    | | +======+========+
            +====+=====+=+  |   |        |    | | | Organization |
            |  Document  |  |   |        |    | | | name         |
            |  doc_id    |--+---+        |    | | | org_type     |
            |  title     |CONTAINS      |    | | +==+=+=+==+====+
            |  doc_type  |              |    | |    ^ | |   ^
            +==+===+=====+              |    | |    | | |   |SUBORDINATE_TO
               |   |                    |    | |    | | |
               |   |MENTIONS            |    | |    | | |CONDUCTED
               v   v                    v    | |    | | v
            +=+==========+           +=+=====+=+=+ +=+=+========+
            |ThreatActor |           |ThreatActor| | Operation  |
            | name       |           |           | | name       |
            +==+=====+===+           +===========+ +============+
               ^     |                                   ^
               |     |ATTRIBUTED_TO -> Incident          |
               |KNOWN_AS                            CONDUCTED
               |                                         |
            +==+==========+                     +========+====+
            |   Person    |----MEMBER_OF------->| Organization|
            | name        |                     +=============+
            | role        |----PARTICIPATED_IN---> Operation
            | country     |
            +=============+

            Incident ----USES----> MITRETechnique
                                   | technique_id |
                                   | name         |
```

### Типи вузлів (12 Node Labels)

| Вузол | Властивості | Джерело |
|-------|------------|---------|
| Incident | incident_id, title, date, severity | sync_incident_to_graph |
| Source | name | sync_incident/ioc_feeds_to_graph |
| ThreatActor | name | sync_incident/person/org_to_graph |
| AttackType | name | sync_incident/document_to_graph |
| Sector | name | sync_incident/document_to_graph |
| MITRETechnique | technique_id, name | sync_incident/document_to_graph |
| IOCIndicator | value, type, threat_level | sync_incident/document/ioc_feeds |
| Person | name, role, country | sync_person_to_graph |
| Organization | name, org_type | sync_org_to_graph |
| Country | name | sync_org_to_graph |
| Operation | name | sync_person/org_to_graph |
| Document | doc_id, title, doc_type | sync_document_to_graph |

### Типи звязків (18+ Relationship Types)

| Звязок | Від -> До | Значення |
|--------|-----------|----------|
| FROM | Incident -> Source | Інцидент з джерела |
| FROM | IOCIndicator -> Source | IOC з фіду |
| ATTRIBUTED_TO | ThreatActor -> Incident | Атрибуція актору |
| HAS_TYPE | Incident -> AttackType | Тип атаки |
| TARGETS | Incident -> Sector | Цільовий сектор |
| USES | Incident -> MITRETechnique | MITRE техніка |
| CONTAINS | Incident -> IOCIndicator | IOC з інциденту |
| CONTAINS | Document -> IOCIndicator | IOC з документа |
| MEMBER_OF | Person -> Organization | Членство |
| PARTICIPATED_IN | Person -> Operation | Участь в операції |
| KNOWN_AS | Person -> ThreatActor | Відомий як |
| SUBORDINATE_TO | Organization -> Organization | Підпорядкування |
| ASSOCIATED_WITH | Organization -> ThreatActor | Звязок з актором |
| BASED_IN | Organization -> Country | Розташування |
| CONDUCTED | Organization -> Operation | Проведена операція |
| MENTIONS | Document -> ThreatActor | Згадка |
| DESCRIBES | Document -> AttackType | Опис типу атаки |
| REFERENCES | Document -> Sector | Посилання на сектор |
| LINKED_TO | IOCIndicator -> MITRETechnique | IOC-техніка |

---

## Потоки даних

### RSS Feed -> Аналіз -> Візуалізація

```
КРОК 1: ЗБІР (rss_parser.py)
  RSS Feed URL -> feedparser.parse(url)
       |
       v
  Для кожного entry:
  is_ukraine_relevant(text)?  --NO--> Відхилити
       |YES
       v
  classify_attack_type(text)   -> 9 категорій
  classify_target_sector(text) -> 9 секторів
  identify_threat_actor(text)  -> 12 акторів з маппінгом
  assign_severity(type,actor)  -> Критичний/Високий/Середній/Низький
  extract_iocs(text)           -> IP, domain, hash, CVE, MITRE
       |
       v
  3-рівнева дедуплікація (URL unique + URL normalize + fuzzy title)
       |
       v
  INSERT INTO incidents + fetch_log

КРОК 2: СКРЕЙПІНГ (scraper.py)
  scrape_article(source_url) -> BeautifulSoup + lxml
       |
  _find_content()  -> 12 сайт-специфічних CSS + 9 generic селекторів
  _extract_images() -> download to data/images/{id}/
  extract_iocs(full_text) -> повторна IOC екстракція
       |
       v
  UPDATE incidents SET full_text, images, ioc_indicators

КРОК 3: ПЕРЕКЛАД (translator.py)
  translate_incident(id)
       |
  Перевірка: і/ї/є/ґ в перших 200 символах? -> Пропустити
       |НІ
  googletrans.translate(chunks_4K, dest=uk)
       |
       v
  UPDATE incidents SET title_uk, description_uk, full_text_uk

КРОК 4: СИНХРОНІЗАЦІЯ (graph_sync.py)
  sync_incident_to_graph(id)
       |
  CREATE Incident, MERGE Source/Actor/Type/Sector/MITRE/IOCs
       |
       v
  UPDATE incidents SET neo4j_synced = NOW()

КРОК 5: ВІЗУАЛІЗАЦІЯ (graph_routes.py + graph.js)
  Browser -> GET /graph -> Cytoscape.js
  JS fetch(/api/graph/data) -> Cypher query -> JSON nodes+edges
  Cytoscape.js render (cola layout, interactive)
```

---

## Система збору даних

### RSS Feeds (config.py - 11 джерел)

| # | Назва | URL | Мова | Завжди релевантний |
|---|-------|-----|------|-------------------|
| 1 | CERT-UA | cert.gov.ua/api/articles/rss | uk | Так |
| 2 | BleepingComputer | bleepingcomputer.com/feed/ | en | Ні |
| 3 | The Record | therecord.media/feed | en | Ні |
| 4 | SecurityWeek | securityweek.com/feed/ | en | Ні |
| 5 | The Hacker News | feeds.feedburner.com/TheHackersNews | en | Ні |
| 6 | Recorded Future | recordedfuture.com/feed | en | Ні |
| 7 | Google TAG | blog.google/threat-analysis-group/rss/ | en | Ні |
| 8 | Microsoft Security | microsoft.com/.../blog/feed/ | en | Ні |
| 9 | CISA Alerts | cisa.gov/cybersecurity-advisories/all.xml | en | Ні |
| 10 | Cisco Talos | blog.talosintelligence.com/rss/ | en | Ні |
| 11 | Mandiant | mandiant.com/resources/blog/rss.xml | en | Ні |

### Класифікація атак (9 типів)

Фішинг, Шкідливе ПЗ, Програма-вимагач, Wiper, DDoS, Експлойт, Шпигунство, Дефейс, Supply Chain

### Цільові сектори (9 секторів)

Державний сектор, Енергетика, Оборона, Фінанси, Телекомунікації, Освіта, Охорона здоровя, Інфраструктура, ЗМІ

### Маппінг акторів загроз (12 записів)

```
UAC-0001 = APT28 (Fancy Bear)
UAC-0002 = Sandworm (APT44)
UAC-0010 = Gamaredon (Armageddon)
UAC-0006 = InvisiMole
apt28 / fancy bear = APT28 (Fancy Bear)
sandworm / apt44 = Sandworm (APT44)
gamaredon / armageddon / shuckworm = Gamaredon (Armageddon)
turla = Turla (Snake / Venomous Bear)
```

### Twitter Fetcher (ТИМЧАСОВО ВИМКНЕНО)

8 акаунтів: ABORIPUU (CERT-UA), dsaboripuu (SSSCIP), TheRecord_Media, BleachingComputer, CISAgov, MsftSecIntel, MandiantIntel, GoogleTAG. Потребує: TWITTER_BEARER_TOKEN.

### LinkedIn Fetcher (ТИМЧАСОВО ВИМКНЕНО)

6 пошукових запитів через Google Custom Search API. Потребує: GOOGLE_CSE_API_KEY + GOOGLE_CSE_ID.

---

## IOC конвеєр

### Джерела IOC

```
1. RSS інциденти (title+desc)  -> incidents.ioc_indicators (JSON)
2. Скрейплені статті (full_text) -> UPDATE incidents.ioc_indicators
3. PDF документи               -> uploaded_documents.ioc_data (JSON)
4. IOC Feeds:
   - ThreatFox (abuse.ch)      -> ioc_indicators_feed table
   - URLhaus (abuse.ch)         -> ioc_indicators_feed table
   - Feodo Tracker (abuse.ch)   -> ioc_indicators_feed table
```

### Regex патерни (ioc_extractor.py - 9 типів)

```
RE_IPV4     \b(\d{1,3}[.\[\.\]]){3}\d{1,3}\b     (+ defanged support)
RE_IPV6     [0-9a-fA-F]{1,4}: groups
RE_DOMAIN   [a-zA-Z0-9-]+(\[\.\]|\.)+[a-zA-Z]{2,} (+ defanged)
RE_URL      (hxxps?|https?|ftp)://[^\s<>]+         (+ defanged hxxp)
RE_MD5      [a-fA-F0-9]{32}
RE_SHA1     [a-fA-F0-9]{40}
RE_SHA256   [a-fA-F0-9]{64}
RE_CVE      CVE-\d{4}-\d{4,}
RE_MITRE    T\d{4}(\.\d{3})?
RE_EMAIL    [a-zA-Z0-9._%+-]+@[domain]
```

### False Positive фільтрація

```
Private IPs:     10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
Common domains:  google.com, microsoft.com, github.com, twitter.com,
                 facebook.com, youtube.com, linkedin.com (40+ виключень)
Trivial hashes:  all-zeros, all-f
SHA subset:      SHA256[:32]==MD5 -> drop MD5; SHA256[:40]==SHA1 -> drop SHA1
```

### Збагачення (ioc_enrichment.py - опціонально)

```
VirusTotal API v3:  GET /ip_addresses/{ip}, /domains/{d}, /files/{hash}
                    -> reputation, detection ratio
                    Rate: ~4 req/min (free), max 5 IOC/type/incident

AbuseIPDB API v2:   GET /check?ipAddress={ip}
                    -> abuse confidence score, total reports
                    Rate: 0.5s delay between requests
```

---

## Графова аналітика (graph_analysis.py)

### NetworkX алгоритми

```
build_networkx_graph()     -> nx.Graph з Neo4j даних
compute_centrality(G)      -> degree, betweenness, pagerank для кожного вузла
detect_communities(G)      -> greedy_modularity_communities
find_shortest_path(G,s,t)  -> nx.shortest_path
get_actor_profile(name)    -> Neo4j Cypher: актор + всі звязки (incidents,
                              attack_types, sectors, techniques, IOCs,
                              persons, organizations)
get_graph_stats()          -> Підрахунок вузлів/звязків за типом
```

### Cytoscape.js візуалізація (graph.js - 454 рядки)

```
Стилі вузлів за типом:
  Incident      -> Червоний коло
  ThreatActor   -> Темно-червоний ромб
  AttackType    -> Помаранчевий трикутник
  Sector        -> Синій квадрат
  Source        -> Зелений коло
  Person        -> Фіолетовий коло
  Organization  -> Коричневий коло
  IOCIndicator  -> Сірий маленький коло
  MITRETechnique-> Жовтий коло
  Country       -> Блакитний коло
  Operation     -> Рожевий коло
  Document      -> Темно-синій коло

Фільтри: actor, sector, attack_type, limit (max 2000)
Layout: cola (force-directed), grid, circle, concentric
Інтерактивність: click -> деталі, zoom, pan, hover
```

---

## Веб-інтерфейс та API

### Flask маршрути (app.py - 35+ маршрутів)

```
DASHBOARD:
  GET  /                          -> dashboard.html
  GET  /api/dashboard/stats       -> JSON статистика

INCIDENTS:
  GET  /incidents                 -> incidents.html (фільтри + пагінація)
  GET  /incidents/<id>            -> incident_detail.html
  GET  /incidents/new             -> incident_form.html
  POST /incidents/new             -> Створити інцидент
  POST /incidents/<id>/delete     -> Видалити
  POST /incidents/<id>/scrape     -> Скрейпити статтю
  POST /incidents/<id>/translate  -> Перекласти
  POST /incidents/<id>/enrich     -> IOC збагачення

PERSONS:
  GET  /persons                   -> persons.html
  GET  /persons/<id>              -> person_detail.html
  POST /persons/import            -> Імпорт з threat_intel_parser

ORGANIZATIONS:
  GET  /organizations             -> organizations.html
  GET  /organizations/<id>        -> organization_detail.html
  POST /organizations/import      -> Імпорт

IOC INDICATORS:
  GET  /ioc                       -> ioc_list.html
  GET  /ioc/<id>                  -> ioc_detail.html
  POST /ioc/fetch                 -> Збір IOC feeds

DOCUMENTS:
  GET  /documents                 -> documents.html
  POST /documents/upload          -> Завантажити + аналіз
  GET  /documents/<id>            -> document_detail.html

GRAPH:  GET  /graph               -> graph.html (Cytoscape.js)
TOOLS:  POST /fetch, /scrape-all, /translate-all
REPORTS: POST /generate-report    -> Генерувати DOCX
STATIC: GET  /images/<path>       -> data/images/
```

### Graph API (graph_routes.py - 8 ендпоінтів)

```
GET  /api/graph/status              -> {available, message}
GET  /api/graph/stats               -> {nodes: {label: count}, edges: {...}}
GET  /api/graph/data?actor=&limit=  -> {nodes, edges} Cytoscape.js format
POST /api/graph/sync                -> sync_all_unsynced()
POST /api/graph/sync/full           -> sync_all_to_graph()
GET  /api/graph/analysis/centrality -> degree, betweenness, pagerank
GET  /api/graph/analysis/communities-> community detection
GET  /api/graph/analysis/actor/<n>  -> actor profile + connections
```

---

## Система планування задач (scheduler.py)

### 5 фонових задач APScheduler

```
1. RSS Fetch      | interval 30 хв  | fetch_all_feeds()     | ЗАВЖДИ
2. Twitter Fetch  | interval 15 хв  | fetch_all_twitter()   | ВИМКНЕНО (потр. API)
3. LinkedIn Fetch | interval 120 хв | fetch_all_linkedin()  | ВИМКНЕНО (потр. CSE)
4. IOC Feeds      | interval 60 хв  | fetch_all_ioc_feeds() | УВІМКНЕНО
5. Daily Pipeline | cron 08:00      | 6-кроковий конвеєр    | ЗАВЖДИ
```

### Daily Pipeline (6 кроків)

```
08:00 -> fetch_all_feeds()
      -> fetch_all_twitter() (opt)
      -> fetch_all_linkedin() (opt)
      -> fetch_all_ioc_feeds() (opt)
      -> scrape_unscraped() + translate_untranslated()
      -> sync_all_unsynced() + generate_daily_report(yesterday)
      -> ~/Desktop/CyberTracker_Report_YYYY-MM-DD.docx
```

---

## Генератор звітів (report_generator.py)

3 типи: daily, weekly, monthly. Формат DOCX (python-docx).

```
Структура: Заголовок -> Статистика -> Severity/Type/Sector таблиці
-> Детальний опис інцидентів (текст UA/EN + IOC + зображення)
-> Нові IOC з фідів -> Рекомендації
Формат: Calibri 8-16pt, color-coded severity, images max 5.5 inches
```

---

## Конфігурація та безпека

### Змінні оточення (.env)

| Змінна | Опис | Без неї |
|--------|------|---------|
| SECRET_KEY | Flask session key | default value |
| NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD | Neo4j connection | Neo4j вимкнено |
| TWITTER_BEARER_TOKEN | Twitter API v2 | Twitter вимкнено |
| GOOGLE_CSE_API_KEY + GOOGLE_CSE_ID | Google Custom Search | LinkedIn вимкнено |
| VIRUSTOTAL_API_KEY | VirusTotal API | VT збагачення вимкнено |
| ABUSEIPDB_API_KEY | AbuseIPDB API | AIPDB збагачення вимкнено |

Система працює без API ключів (RSS + IOC feeds). Кожен ключ розширює функціональність.

### Безпека

- API ключі: .env -> .gitignore, python-dotenv
- Аутентифікація: БЕЗ (dev mode). Рекомендовано: Flask-Login + RBAC
- SQL injection: SQLAlchemy параметризовані запити
- XSS: Jinja2 auto-escaping
- File upload: whitelist (pdf/txt/csv/docx) + 50MB limit

---

## Обробка помилок та стійкість

| Компонент | Недоступний | Результат |
|-----------|------------|-----------|
| RSS Feed | timeout/error | Log, skip, continue |
| Web scraping | HTTP/parse error | Log, use RSS description |
| Google Translate | API/rate limit | Log, keep original text |
| Neo4j | not running | is_available()=False, system works |
| VirusTotal | no API key | Skip enrichment |
| AbuseIPDB | no API key | Skip enrichment |
| Twitter API | no token | TWITTER_ENABLED=False |
| LinkedIn/CSE | no keys | LINKEDIN_ENABLED=False |
| PyMuPDF | DLL missing | Fallback to PyPDF2 |
| IOC Feed | timeout | Log, continue with others |

---

## Масштабування

### Поточна (Development)

Single process: Flask debug + APScheduler in-process. SQLite single-writer. Limits: 1-10 users, ~100K incidents, ~1M IOCs.

### Рекомендована (Production)

```
Nginx (reverse proxy, SSL) -> Gunicorn (4-8 workers) + Celery (async tasks)
Redis (broker + cache) -> PostgreSQL (replaces SQLite) + Neo4j Cluster
```

---

## Lifecycle: Запуск (run.py)

```
python run.py
  -> logging.basicConfig(level=INFO)
  -> init_db()             # data/ + all tables
  -> migrate_db()          # ALTER TABLE for new columns
  -> init_graph_schema()   # Neo4j constraints (if enabled)
  -> atexit.register(close_driver)
  -> app = create_app()    # Flask factory + routes + blueprint
  -> start_scheduler(app)  # 5 background jobs
  -> app.run(host=0.0.0.0, port=5000, debug=True)
```

---

## Залежності

| Пакет | Версія | Використання |
|-------|--------|-------------|
| Flask | 3.1.0 | Web framework |
| SQLAlchemy | 2.0.36 | ORM |
| feedparser | 6.0.11 | RSS |
| APScheduler | 3.10.4 | Background jobs |
| requests | 2.32.3 | HTTP client |
| googletrans | 4.0.0rc1 | Translation |
| python-docx | 1.1.2 | DOCX reports |
| beautifulsoup4 | 4.12.3 | HTML parsing |
| lxml | 5.3.0 | XML/HTML parser |
| python-dotenv | 1.0.1 | .env loading |
| neo4j | >=5.20 | Neo4j driver |
| networkx | 3.4.2 | Graph analysis |
| tweepy | 4.14.0 | Twitter API |

Опціонально: PyMuPDF (fitz), PyPDF2

---

## Статистика коду

| Категорія | Кількість |
|-----------|-----------|
| Python файли | 22 |
| Рядки Python | 7,448 |
| HTML шаблони | 14 (2,305 рядків) |
| JavaScript | 3 файли (578 рядків) |
| CSS | 1 файл (123 рядки) |
| Таблиці SQLite | 6 (20+ індексів) |
| Вузли Neo4j | 12 типів |
| Звязки Neo4j | 18+ типів |
| Flask маршрути | 35+ |
| Graph API | 8 ендпоінтів |
| Фонові задачі | 5 |
| RSS джерел | 11 |
| IOC regex | 9 патернів |
| Threat actors | 12 (з alias mapping) |
| Attack types | 9 категорій |
| Target sectors | 9 секторів |

---

*Документація архітектури CyberTracker UA*
*Дата створення: 15 лютого 2026*
