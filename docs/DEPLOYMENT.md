# Розгортання CyberTracker UA

Повна інструкція з встановлення, налаштування та розгортання системи.

---

## Зміст

- [Системні вимоги](#системні-вимоги)
- [Базове встановлення](#базове-встановлення)
- [Налаштування Neo4j](#налаштування-neo4j)
- [Налаштування зовнішніх API](#налаштування-зовнішніх-api)
- [Конфігурація](#конфігурація)
- [Продакшн розгортання](#продакшн-розгортання)
- [Моніторинг та обслуговування](#моніторинг-та-обслуговування)
- [Резервне копіювання](#резервне-копіювання)
- [Вирішення проблем](#вирішення-проблем)

---

## Системні вимоги

### Мінімальні вимоги (розробка)

| Компонент | Вимога |
|-----------|--------|
| ОС | Windows 10+, Ubuntu 20.04+, macOS 11+ |
| Python | 3.10 або новіше |
| RAM | 2 GB |
| Диск | 500 MB вільного місця |
| Мережа | Доступ до Інтернету |

### Рекомендовані вимоги (продакшн)

| Компонент | Вимога |
|-----------|--------|
| Python | 3.12+ |
| RAM | 4-8 GB |
| Диск | 5-10 GB SSD |
| CPU | 2+ ядра |
| Neo4j | 5.20+ (4 GB RAM для JVM) |

---

## Базове встановлення

### Windows

```powershell
# 1. Встановити Python 3.12+ з https://python.org
# (обов'язково позначте "Add Python to PATH")

# 2. Клонувати репозиторій
git clone https://github.com/your-repo/cybertracker-ua.git
cd cybertracker-ua

# 3. Створити віртуальне середовище
python -m venv venv
venv\Scriptsctivate

# 4. Встановити залежності
pip install -r requirements.txt

# 5. Додаткові залежності для PDF
pip install PyMuPDF PyPDF2 reportlab

# 6. Створити файл конфігурації
copy .env.example .env
# Відредагуйте .env за потребою

# 7. Запустити
python run.py
```

### Linux (Ubuntu/Debian)

```bash
# 1. Встановити Python та залежності
sudo apt update
sudo apt install python3.12 python3.12-venv python3-pip git

# 2. Клонувати репозиторій
git clone https://github.com/your-repo/cybertracker-ua.git
cd cybertracker-ua

# 3. Створити віртуальне середовище
python3.12 -m venv venv
source venv/bin/activate

# 4. Встановити залежності
pip install -r requirements.txt
pip install PyMuPDF PyPDF2 reportlab

# 5. Конфігурація
cp .env.example .env
nano .env

# 6. Запустити
python run.py
```

### macOS

```bash
# 1. Встановити Python через Homebrew
brew install python@3.12

# 2. Клонувати та налаштувати
git clone https://github.com/your-repo/cybertracker-ua.git
cd cybertracker-ua
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install PyMuPDF PyPDF2 reportlab

# 3. Конфігурація та запуск
cp .env.example .env
python run.py
```

---

## Налаштування Neo4j

Neo4j - опціональний компонент для графового аналізу. Система працює і без нього.

### Встановлення Neo4j

#### Windows

1. Завантажте Neo4j Community Edition з https://neo4j.com/download/
2. Встановіть та запустіть Neo4j Desktop
3. Створіть нову базу даних
4. Запам'ятайте пароль

#### Linux

```bash
# Додати репозиторій Neo4j
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install neo4j

# Запустити
sudo systemctl start neo4j
sudo systemctl enable neo4j

# Встановити пароль (перший вхід)
cypher-shell -u neo4j -p neo4j
# Вам буде запропоновано змінити пароль
```

#### Docker

```bash
docker run -d   --name neo4j   -p 7474:7474 -p 7687:7687   -e NEO4J_AUTH=neo4j/your_password   -v neo4j_data:/data   neo4j:5.20-community
```

### Підключення CyberTracker до Neo4j

Відредагуйте `.env`:

```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

Перезапустіть додаток. В консолі має з'явитися:

```
Neo4j: Connected to bolt://localhost:7687
Neo4j: Schema initialized (12/12 constraints/indexes)
```

### Без аутентифікації Neo4j

Якщо Neo4j налаштований без аутентифікації:

```bash
NEO4J_PASSWORD=noauth
```

Система автоматично визначить режим та підключиться без аутентифікації.

### Перша синхронізація

Після підключення Neo4j:

1. Натисніть **"Синхр. все в Neo4j"** в навігації
2. Або відвідайте URL: `/sync-all-graph`
3. Або використовуйте API: `POST /api/graph/sync`

Синхронізуються:
- Всі інциденти (без відмітки neo4j_synced)
- Всі загрозливі особи
- Всі організації
- Всі документи (без відмітки neo4j_synced)
- IOC індикатори (critical/high, до 500 штук)

---

## Налаштування зовнішніх API

### Twitter/X API

1. Зареєструйтесь на https://developer.twitter.com
2. Створіть проект та додаток
3. Отримайте Bearer Token

```bash
TWITTER_BEARER_TOKEN=your_bearer_token_here
```

### VirusTotal API

1. Зареєструйтесь на https://www.virustotal.com
2. Перейдіть в Settings > API key
3. Скопіюйте API key

```bash
VIRUSTOTAL_API_KEY=your_api_key_here
```

**Обмеження безкоштовного плану:** 4 запити/хв, 500 запитів/день

### AbuseIPDB API

1. Зареєструйтесь на https://www.abuseipdb.com
2. Перейдіть в Account > API

```bash
ABUSEIPDB_API_KEY=your_api_key_here
```

**Обмеження безкоштовного плану:** 1000 запитів/день

### Google Custom Search (для LinkedIn)

1. Створіть пошукову систему: https://programmablesearchengine.google.com/
2. Налаштуйте пошук по сайту linkedin.com
3. Отримайте API key з Google Cloud Console (увімкніть Custom Search API)

```bash
GOOGLE_CSE_API_KEY=your_api_key
GOOGLE_CSE_ID=your_search_engine_id
```

---

## Конфігурація

### Повний список змінних .env

```bash
# === Neo4j (опціонально) ===
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=               # Порожній = вимкнено

# === Twitter (опціонально) ===
TWITTER_BEARER_TOKEN=

# === Збагачення IOC (опціонально) ===
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# === LinkedIn (опціонально) ===
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_ID=
```

### Параметри config.py

Ці параметри налаштовуються безпосередньо в `config.py`:

#### Розклад

```python
FETCH_INTERVAL_MINUTES = 30          # RSS оновлення
IOC_FETCH_INTERVAL_MINUTES = 60      # IOC фіди
TWITTER_FETCH_INTERVAL_MINUTES = 15  # Twitter
LINKEDIN_FETCH_INTERVAL_MINUTES = 120 # LinkedIn
```

#### Пагінація

```python
INCIDENTS_PER_PAGE = 20
IOC_PER_PAGE = 30
DOCS_PER_PAGE = 20
```

#### Документи

```python
UPLOAD_DIR = os.path.join(BASE_DIR, 'data', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'csv', 'docx'}
MAX_UPLOAD_SIZE_MB = 50
```

#### RSS-канали

Додайте або видаліть канали в масиві `RSS_FEEDS`:

```python
RSS_FEEDS = [
    {
        'name': 'CERT-UA',
        'url': 'https://cert.gov.ua/api/articles/rss',
        'language': 'uk',
        'always_relevant': True  # Не фільтрується за ключовими словами
    },
    {
        'name': 'New Source',
        'url': 'https://example.com/feed',
        'language': 'en',
        'always_relevant': False  # Фільтрується за UKRAINE_KEYWORDS
    },
]
```

#### Ключові слова фільтрації

```python
UKRAINE_KEYWORDS = [
    'ukraine', 'ukrainian', 'cert-ua', 'uac-0',
    'sandworm', 'apt28', 'gamaredon', 'turla',
    # ... додайте свої
]
```

---

## Продакшн розгортання

### Gunicorn (Linux)

```bash
# Встановити
pip install gunicorn

# Запустити
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()

# Або з конфігурацією
gunicorn -w 4 -b 0.0.0.0:5000   --timeout 120   --access-logfile access.log   --error-logfile error.log   app:create_app()
```

### Systemd сервіс (Linux)

```ini
# /etc/systemd/system/cybertracker.service
[Unit]
Description=CyberTracker UA
After=network.target neo4j.service

[Service]
Type=simple
User=cybertracker
WorkingDirectory=/opt/cybertracker-ua
Environment=PATH=/opt/cybertracker-ua/venv/bin
ExecStart=/opt/cybertracker-ua/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:create_app()
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cybertracker
sudo systemctl start cybertracker
```

### Nginx reverse proxy

```nginx
server {
    listen 80;
    server_name cybertracker.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /opt/cybertracker-ua/static/;
        expires 1d;
    }

    client_max_body_size 50M;  # Для завантаження PDF
}
```

### Docker

```dockerfile
# Dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt     && pip install PyMuPDF PyPDF2 gunicorn

COPY . .

RUN mkdir -p data/uploads data/images

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:create_app()"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./data:/app/data
      - ./.env:/app/.env
    depends_on:
      - neo4j
    restart: always

  neo4j:
    image: neo4j:5.20-community
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/your_password
    volumes:
      - neo4j_data:/data
    restart: always

volumes:
  neo4j_data:
```

---

## Моніторинг та обслуговування

### Логування

Система використовує Python logging з рівнем INFO:

```
2026-02-15 08:00:00 [INFO] rss_parser: Fetching CERT-UA...
2026-02-15 08:00:02 [INFO] rss_parser: CERT-UA: found 3 relevant, added 1 new
2026-02-15 08:00:05 [INFO] ioc_feed_fetcher: Fetching ThreatFox...
2026-02-15 08:00:10 [INFO] graph_sync: Synced 5 incidents to Neo4j
```

### Перевірка стану

```bash
# Перевірка сервера
curl http://127.0.0.1:5000/

# Перевірка Neo4j
curl http://127.0.0.1:5000/api/graph/status

# Статистика
curl http://127.0.0.1:5000/api/graph/stats
```

### Обслуговування бази даних

SQLite не потребує спеціального обслуговування. Для оптимізації:

```bash
# Оптимізація SQLite (виконати раз на місяць)
python -c "
from database import get_session
s = get_session()
s.execute('VACUUM')
s.close()
print('Database optimized')
"
```

---

## Резервне копіювання

### SQLite

```bash
# Копія бази даних
cp data/cybertracker.db backup/cybertracker_$(date +%Y%m%d).db

# Автоматичне щоденне копіювання (cron)
0 2 * * * cp /opt/cybertracker-ua/data/cybertracker.db /backup/cybertracker_$(date +\%Y\%m\%d).db
```

### Neo4j

```bash
# Зупинити Neo4j перед копіюванням
sudo systemctl stop neo4j
cp -r /var/lib/neo4j/data/databases/ /backup/neo4j_$(date +%Y%m%d)/
sudo systemctl start neo4j

# Або через neo4j-admin
neo4j-admin database dump --to-path=/backup/ neo4j
```

### Завантажені документи

```bash
# Копія завантажених файлів
tar czf backup/uploads_$(date +%Y%m%d).tar.gz data/uploads/
```

---

## Вирішення проблем

### Проблема: Порт 5000 зайнятий

```bash
# Windows
netstat -ano | findstr :5000
taskkill /F /PID <pid>

# Linux
lsof -i :5000
kill -9 <pid>
```

### Проблема: PyMuPDF не встановлюється

PyMuPDF (fitz) може мати проблеми на деяких платформах. Система автоматично використовує PyPDF2 як fallback.

```bash
# Спробуйте встановити окремо
pip install PyMuPDF

# Якщо не вдається, встановіть PyPDF2
pip install PyPDF2
```

### Проблема: Neo4j не підключається

```bash
# Перевірте чи Neo4j запущений
# Windows: Neo4j Desktop > Start
# Linux:
sudo systemctl status neo4j

# Перевірте порт
curl http://localhost:7474

# Перевірте пароль в .env
# NEO4J_PASSWORD має відповідати паролю Neo4j
```

### Проблема: Помилка кодування (cp1252)

На Windows можуть бути проблеми з українськими символами:

```bash
# Встановити UTF-8 кодування
set PYTHONIOENCODING=utf-8
python run.py

# Або в PowerShell
$env:PYTHONIOENCODING="utf-8"
python run.py
```

### Проблема: googletrans помилки

googletrans використовує неофіційний API і може бути нестабільним:

```bash
# Перевстановити
pip install googletrans==4.0.0rc1

# Якщо помилки повторюються, переклад можна пропустити
# Система працює і без перекладу (відображається оригінал)
```

### Проблема: Великий розмір бази даних

```bash
# Перевірити розмір
du -sh data/cybertracker.db

# Оптимізувати
python -c "
from database import get_session
s = get_session()
s.execute('VACUUM')
s.close()
"

# Видалити старі записи fetch_log (опціонально)
python -c "
from database import get_session
from models import FetchLog
from datetime import datetime, timedelta
s = get_session()
old = datetime.utcnow() - timedelta(days=30)
deleted = s.query(FetchLog).filter(FetchLog.fetched_at < old).delete()
s.commit()
print(f'Deleted {deleted} old log entries')
s.close()
"
```

---

## Безпека

### Рекомендації

1. **API ключі**: зберігайте тільки в `.env` (в `.gitignore`)
2. **Neo4j**: змініть пароль за замовчуванням
3. **Firewall**: обмежте доступ до портів 5000, 7474, 7687
4. **HTTPS**: використовуйте Nginx з SSL-сертифікатом
5. **Аутентифікація**: додайте Flask-Login для продакшн
6. **Оновлення**: регулярно оновлюйте залежності

### Приклад SSL з Let's Encrypt

```bash
# Встановити certbot
sudo apt install certbot python3-certbot-nginx

# Отримати сертифікат
sudo certbot --nginx -d cybertracker.example.com
```

---

*Документація розгортання CyberTracker UA*
