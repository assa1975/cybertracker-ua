# Cybersecurity News Aggregator - Plan

## Stack
- Python 3
- MongoDB (pymongo)
- Flask (web UI)
- feedparser (RSS)
- NewsAPI (API)
- APScheduler (periodic fetching)

## Structure
```
proekt/
├── config.py          # Configuration (MongoDB, API keys, RSS feeds)
├── models.py          # MongoDB models/helpers
├── scrapers/
│   ├── __init__.py
│   ├── rss_scraper.py    # RSS feed parser
│   └── newsapi_scraper.py # NewsAPI client
├── app.py             # Flask web app + routes
├── templates/
│   ├── base.html
│   └── index.html
├── static/
│   └── style.css
├── scheduler.py       # APScheduler for periodic fetching
├── main.py            # Entry point
└── requirements.txt
```

## Features
1. Fetch news from RSS feeds (The Hacker News, BleepingComputer, Krebs, etc.)
2. Fetch news from NewsAPI by cybersecurity keywords
3. Store in MongoDB with deduplication by URL
4. Web UI with search, filtering by source/date
5. Scheduled auto-fetch every 30 minutes
