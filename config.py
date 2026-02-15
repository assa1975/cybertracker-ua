import os
from dotenv import load_dotenv

# Load .env file if exists
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Database ---
DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'cybertracker.db')
DATABASE_URI = f"sqlite:///{DATABASE_PATH}"

# --- Flask ---
SECRET_KEY = os.getenv('SECRET_KEY', 'cybertracker-ua-local-dev-key')

# --- Neo4j Graph Database ---
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', '')
NEO4J_ENABLED = bool(NEO4J_PASSWORD)

# --- Twitter/X API ---
TWITTER_BEARER_TOKEN = os.getenv('TWITTER_BEARER_TOKEN', '')
TWITTER_ENABLED = bool(TWITTER_BEARER_TOKEN)

# Accounts to monitor for Ukraine cyber news
TWITTER_ACCOUNTS = [
    'ABORIPUU',         # CERT-UA official
    'dsaboripuu',       # SSSCIP Ukraine
    'TheRecord_Media',
    'BleachingComputer',  # BleepingComputer
    'CISAgov',
    'MsftSecIntel',     # Microsoft Threat Intelligence
    'MandiantIntel',
    'GoogleTAG',        # Google Threat Analysis Group
]
TWITTER_FETCH_INTERVAL_MINUTES = 15

# --- VirusTotal ---
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)

# --- AbuseIPDB ---
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY)

# --- RSS Feeds ---
RSS_FEEDS = [
    {
        'name': 'CERT-UA',
        'url': 'https://cert.gov.ua/api/articles/rss',
        'language': 'uk',
        'always_relevant': True,
    },
    {
        'name': 'BleepingComputer',
        'url': 'https://www.bleepingcomputer.com/feed/',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'The Record',
        'url': 'https://therecord.media/feed',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'SecurityWeek',
        'url': 'https://www.securityweek.com/feed/',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'The Hacker News',
        'url': 'https://feeds.feedburner.com/TheHackersNews',
        'language': 'en',
        'always_relevant': False,
    },
    # --- New Threat Intelligence Feeds ---
    {
        'name': 'Recorded Future',
        'url': 'https://www.recordedfuture.com/feed',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'Google TAG',
        'url': 'https://blog.google/threat-analysis-group/rss/',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'Microsoft Security',
        'url': 'https://www.microsoft.com/en-us/security/blog/feed/',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'CISA Alerts',
        'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'Cisco Talos',
        'url': 'https://blog.talosintelligence.com/rss/',
        'language': 'en',
        'always_relevant': False,
    },
    {
        'name': 'Mandiant',
        'url': 'https://www.mandiant.com/resources/blog/rss.xml',
        'language': 'en',
        'always_relevant': False,
    },
]

# --- Ukraine relevance keywords (case-insensitive) ---
UKRAINE_KEYWORDS = [
    'ukraine', 'ukrainian', 'україн', 'cert-ua', 'uac-0',
    'sandworm', 'apt28', 'apt44', 'fancy bear', 'voodoo bear',
    'gamaredon', 'armageddon', 'shuckworm', 'turla',
    'industroyer', 'whispergate', 'hermetic', 'caddywiper',
    'prestige', 'swiftslicer', 'wrecksteel',
    'gru', 'гру', 'фсб', 'fsb',
]

# --- Attack type classification keywords ---
ATTACK_TYPE_KEYWORDS = {
    'Фішинг': ['phishing', 'spearphishing', 'фішинг', 'credential harvesting'],
    'Шкідливе ПЗ': ['malware', 'trojan', 'backdoor', 'rat ', 'шкідлив'],
    'Програма-вимагач': ['ransomware', 'ransom', 'вимагач'],
    'Wiper': ['wiper', 'destructive', 'знищен'],
    'DDoS': ['ddos', 'denial of service', 'ддос'],
    'Експлойт': ['exploit', 'vulnerability', 'cve-', 'zero-day', 'вразлив'],
    'Шпигунство': ['espionage', 'spying', 'шпигун', 'reconnaissance'],
    'Дефейс': ['defacement', 'deface', 'дефейс'],
    'Supply Chain': ['supply chain', 'supply-chain', 'ланцюг постачання'],
}

# --- Target sector classification keywords ---
SECTOR_KEYWORDS = {
    'Державний сектор': ['government', 'державн', 'ministry', 'міністерств', 'state agency'],
    'Енергетика': ['energy', 'енергет', 'power grid', 'електро'],
    'Оборона': ['defense', 'military', 'оборон', 'військов', 'збройн'],
    'Фінанси': ['financial', 'banking', 'bank', 'фінанс', 'банк'],
    'Телекомунікації': ['telecom', 'телеком', 'isp', 'провайдер'],
    'Освіта': ['education', 'university', 'освіт', 'університет'],
    "Охорона здоров'я": ['health', 'hospital', 'медичн', 'лікарн'],
    'Інфраструктура': ['infrastructure', 'інфраструктур', 'critical infrastructure', 'критичн'],
    'ЗМІ': ['media', 'journalist', 'змі', 'журналіст', 'news outlet'],
}

# --- Severity levels ---
SEVERITY_LEVELS = ['Критичний', 'Високий', 'Середній', 'Низький']

# --- Threat actor mapping ---
THREAT_ACTORS = {
    'uac-0001': 'UAC-0001 (APT28 / Fancy Bear)',
    'uac-0002': 'UAC-0002 (Sandworm / APT44)',
    'uac-0010': 'UAC-0010 (Gamaredon / Armageddon)',
    'uac-0006': 'UAC-0006 (InvisiMole)',
    'apt28': 'APT28 (Fancy Bear)',
    'fancy bear': 'APT28 (Fancy Bear)',
    'sandworm': 'Sandworm (APT44)',
    'apt44': 'Sandworm (APT44)',
    'gamaredon': 'Gamaredon (Armageddon)',
    'armageddon': 'Gamaredon (Armageddon)',
    'turla': 'Turla (Snake / Venomous Bear)',
    'shuckworm': 'Gamaredon (Armageddon)',
}

# --- Scheduler ---
FETCH_INTERVAL_MINUTES = 30

# --- Pagination ---
INCIDENTS_PER_PAGE = 20
