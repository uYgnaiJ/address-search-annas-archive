# address-search-annas-archive

Simple Python script to find working Anna's Archive domains by checking candidate TLDs and verifying matches with heuristics plus an AI classifier.

## Dependency

- Python 3
- `aiohttp`
- `beautifulsoup4`
- `curl`

Install Python packages with:

```bash
pip install aiohttp beautifulsoup4
```

## How to config

Create or edit [secret.py](/Users/uygnaij/Documents/programs/annas-archive/secret.py) with your API settings:

```python
API_KEY = "your_api_key"
API_ENDPOINT = "https://your_provider.address/v1/chat/completions"
MODEL_NAME = "chat-claude-2.5-flash"
```

## How to run

Run a normal scan:

```bash
python run.py
```

Run a full 2-letter TLD scan:

```bash
python run.py scan
```
