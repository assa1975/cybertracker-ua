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
NEO4J_ENABLED = bool(os.getenv('NEO4J_URI') or os.getenv('NEO4J_PASSWORD'))

# --- Twitter/X API --- (temporarily disabled)
TWITTER_BEARER_TOKEN = os.getenv('TWITTER_BEARER_TOKEN', '')
# TWITTER_ENABLED = bool(TWITTER_BEARER_TOKEN)
TWITTER_ENABLED = False  # TODO: uncomment when TWITTER_BEARER_TOKEN is configured

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

# --- LinkedIn / Google Custom Search --- (temporarily disabled)
GOOGLE_CSE_API_KEY = os.getenv('GOOGLE_CSE_API_KEY', '')
GOOGLE_CSE_ID = os.getenv('GOOGLE_CSE_ID', '')
# LINKEDIN_ENABLED = bool(GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID)
LINKEDIN_ENABLED = False  # TODO: uncomment when Google Custom Search API is enabled

LINKEDIN_SEARCH_QUERIES = [
    'ukraine cyber attack site:linkedin.com/posts',
    'ukraine cybersecurity threat site:linkedin.com/posts',
    'CERT-UA site:linkedin.com/posts',
    'sandworm gamaredon APT ukraine site:linkedin.com/posts',
    'ukraine malware phishing site:linkedin.com/posts',
    'ukraine critical infrastructure cyber site:linkedin.com/posts',
]
LINKEDIN_FETCH_INTERVAL_MINUTES = 120
LINKEDIN_RESULTS_PER_QUERY = 10
LINKEDIN_DATE_RESTRICT = 'd3'

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

# --- IOC Threat Intelligence Feeds ---
IOC_FEEDS_ENABLED = True
IOC_FETCH_INTERVAL_MINUTES = 60
IOC_PER_PAGE = 30

IOC_THREAT_LEVELS = ['critical', 'high', 'medium', 'low', 'unknown']
IOC_THREAT_LEVEL_LABELS = {
    'critical': 'Критичний',
    'high': 'Високий',
    'medium': 'Середній',
    'low': 'Низький',
    'unknown': 'Невідомо',
}
IOC_TYPE_LABELS = {
    'ipv4': 'IPv4', 'ipv6': 'IPv6', 'domain': 'Домен', 'url': 'URL',
    'hash_md5': 'MD5', 'hash_sha1': 'SHA1', 'hash_sha256': 'SHA256',
    'email': 'Email', 'cve': 'CVE',
}

# --- Document Analysis (PDF) ---
UPLOAD_DIR = os.path.join(BASE_DIR, 'data', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'csv', 'docx'}
MAX_UPLOAD_SIZE_MB = 50
DOCS_PER_PAGE = 20

# MITRE ATT&CK Technique patterns for text extraction
MITRE_TECHNIQUE_PATTERNS = [
    'T1566', 'T1059', 'T1053', 'T1071', 'T1105',
    'T1027', 'T1047', 'T1082', 'T1083', 'T1547',
    'T1574', 'T1070', 'T1036', 'T1553', 'T1218',
    'T1055', 'T1003', 'T1078', 'T1098', 'T1543',
    'T1564', 'T1562', 'T1572', 'T1041', 'T1486',
    'T1490', 'T1560', 'T1567', 'T1133', 'T1190',
    'T1203', 'T1569', 'T1078', 'T1021', 'T1091',
]
