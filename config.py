import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Database ---
DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'cybertracker.db')
DATABASE_URI = f"sqlite:///{DATABASE_PATH}"

# --- Flask ---
SECRET_KEY = 'cybertracker-ua-local-dev-key'

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
