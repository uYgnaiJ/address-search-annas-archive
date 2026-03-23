import asyncio
import subprocess
import json
import re
import os
import argparse
import logging
import aiohttp
from bs4 import BeautifulSoup
import secret

# ------------------------------
# CONFIGURATION
# ------------------------------
API_KEY = secret.API_KEY
API_ENDPOINT = secret.API_ENDPOINT
MODEL_NAME = secret.MODEL_NAME

BASE_NAME = "annas-archive"
DOMAINS_FILE = "domain"

CONCURRENCY_LIMIT = 10
MAX_RETRIES = 3
API_TIMEOUT = 20

# ------------------------------
# LOGGING
# ------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ------------------------------
# TLDS
# ------------------------------
VALID_2CHAR_TLDS = [
    'ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az',
    'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm', 'bn', 'bo', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz',
    'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv', 'cw', 'cx', 'cy', 'cz',
    'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ee', 'eg', 'eh', 'er', 'es', 'et', 'eu',
    'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw', 'gy',
    'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'in', 'io', 'iq', 'ir', 'is', 'it',
    'je', 'jm', 'jo', 'jp', 'ke', 'kg', 'kh', 'ki', 'km', 'kn', 'kp', 'kr', 'kw', 'ky', 'kz',
    'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly',
    'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz',
    'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz',
    'om', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py',
    'qa', 're', 'ro', 'rs', 'ru', 'rw',
    'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv', 'sx', 'sy', 'sz',
    'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tr', 'tt', 'tv', 'tw', 'tz',
    'ua', 'ug', 'uk', 'um', 'us', 'uy', 'uz',
    'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'yu', 'za', 'zm', 'zw'
]

# ------------------------------
# COMMAND-LINE
# ------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Anna's Archive Domain Scanner")
    parser.add_argument('command', nargs='?', default=None, help='scan: full TLD scan')
    return parser.parse_args()

# ------------------------------
# FILE MANAGEMENT
# ------------------------------
def load_saved_domains():
    if os.path.exists(DOMAINS_FILE):
        try:
            with open(DOMAINS_FILE, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            if domains:
                logger.info(f"Loaded {len(domains)} saved domains")
                for d in domains[:5]:
                    logger.info(f"  - {d}")
                if len(domains) > 5:
                    logger.info(f"  ... and {len(domains) - 5} more")
                return domains
        except Exception as e:
            logger.warning(f"Could not load: {e}")
    return []

def append_domain(domain):
    try:
        with open(DOMAINS_FILE, 'a') as f:
            f.write(domain + '\n')
    except Exception as e:
        logger.error(f"Save failed: {e}")

def domain_exists(domain):
    if not os.path.exists(DOMAINS_FILE):
        return False
    with open(DOMAINS_FILE, 'r') as f:
        return domain in [line.strip() for line in f]

# ------------------------------
# CURL FETCH (Subprocess - More Reliable)
# ------------------------------
def fetch_with_curl(url, max_retries=3):
    """
    Uses curl subprocess - proven to work with these domains.
    """
    cmd = [
        "curl", "-s", "-L",
        "-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "--connect-timeout", "15",
        "-k",  # Allow insecure SSL (critical for these domains!)
        url
    ]
    
    for attempt in range(max_retries):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0 and len(result.stdout) > 300:
                return result.stdout
        except Exception as e:
            if attempt < max_retries - 1:
                continue
    
    return None

# ------------------------------
# HEURISTIC
# ------------------------------
def quick_verify(html_content):
    """Check for Anna's Archive signatures."""
    if not html_content:
        return False, "No content"
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.find('title')
        title_text = title.text.lower() if title else ""
        body_text = soup.get_text()[:4000].lower()
        
        # Check title first
        if "anna" in title_text and "archive" in title_text:
            return True, "Title match"
        
        if "libgen" in title_text or "z-library" in title_text or "sci-hub" in title_text:
            return True, "Title: library signal"
        
        # Body signals
        signals = {
            "anna's archive": "Name found",
            "annas archive": "Name found",
            "libgen is non-profit": "LibGen mention",
            "library genesis": "Library Genesis",
            "z-library": "Z-Library",
            "sci-hub": "Sci-Hub",
            "annas archive needs your help": "Donation message"
        }
        
        for signal, reason in signals.items():
            if signal in body_text:
                return True, f"Body: {reason}"
        
        if "anna" in body_text:
            library_refs = ["libgen", "z-library", "zlibrary", "sci-hub", "library genesis"]
            for ref in library_refs:
                if ref in body_text:
                    return True, f"Anna + {ref}"
        
    except Exception as e:
        logger.debug(f"Parse error: {e}")
    
    return False, "No signal"

# ------------------------------
# AI VERIFIER
# ------------------------------
async def verify_with_ai(session, url, html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    title = soup.find('title')
    title_text = title.text if title else "No title"
    body_text = soup.get_text()[:2000]

    system_prompt = """You are a website classifier. 
Does this website appear to be Anna's Archive (the shadow library that indexes LibGen, Sci-Hub, Z-Library)?
Look for: Anna's Archive branding, LibGen/Z-Library/Sci-Hub references, donation calls, multilingual support.
Return JSON: {"is_annas_archive": true/false, "reason": "why"}"""

    user_prompt = f"Title: {title_text}\n\nContent: {body_text[:1500]}"

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1
    }

    for attempt in range(MAX_RETRIES):
        try:
            async with session.post(API_ENDPOINT, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)) as response:
                if response.status == 200:
                    data = await response.json()
                    content = data['choices'][0]['message']['content']
                    
                    try:
                        result = json.loads(content)
                        return result.get('is_annas_archive', False), result.get('reason', 'No reason')
                    except:
                        match = re.search(r'\{.*?\}', content, re.DOTALL)
                        if match:
                            result = json.loads(match.group(0))
                            return result.get('is_annas_archive', False), result.get('reason', 'No reason')
                            
                elif response.status == 429:
                    await asyncio.sleep(2 * (2 ** attempt))
                    
        except asyncio.TimeoutError:
            logger.debug(f"AI timeout for {url}")
        except Exception as e:
            logger.debug(f"AI error: {e}")
        
        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(2)
    
    return False, "AI failed"

# ------------------------------
# DOMAIN CHECKER
# ------------------------------
async def check_domain(session, semaphore, tld):
    url = f"https://{BASE_NAME}.{tld}"
    
    async with semaphore:
        logger.info(f"[*] Checking {url}...")
        
        # Use curl (subprocess) - more reliable for these domains
        html = fetch_with_curl(url, max_retries=3)
        
        if not html or len(html) < 300:
            logger.debug(f"  -> Fetch failed")
            return None
        
        # Heuristic check
        is_likely, reason = quick_verify(html)
        
        if is_likely:
            logger.info(f"[✅ HEURISTIC PASSED] {url} - {reason}")
            is_verified, ai_reason = await verify_with_ai(session, url, html)
            if is_verified:
                logger.info(f"[✅ AI VERIFIED] {url} - {ai_reason}")
                return url
            else:
                logger.info(f"[❌ AI REJECTED] {url} - {ai_reason}")
                return None
        
        # Check with AI anyway
        logger.debug(f"  -> Heuristic inconclusive, checking AI...")
        is_verified, ai_reason = await verify_with_ai(session, url, html)
        
        if is_verified:
            logger.info(f"[✅ AI VERIFIED] {url} - {ai_reason}")
            return url
        else:
            logger.debug(f"  -> AI rejected: {ai_reason}")
            return None

# ------------------------------
# WIKIPEDIA
# ------------------------------
async def get_wikipedia_domains():
    logger.info("Fetching Wikipedia...")
    
    # Use curl for Wikipedia too (more reliable)
    cmd = [
        "curl", "-s", "-L",
        "-A", "AI-Domain-Scanner/1.0",
        "--connect-timeout", "10",
        "https://en.wikipedia.org/wiki/Anna's_Archive"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            html = result.stdout
            soup = BeautifulSoup(html, 'html.parser')
            infobox = soup.find('table', class_='infobox')
            
            found_tlds = []
            if infobox:
                links = infobox.find_all('a', href=True)
                for link in links:
                    href = link.get('href', '')
                    match = re.search(r'annas-archive\.([a-z]{2,})', href, re.IGNORECASE)
                    if match:
                        tld = match.group(1)
                        if tld not in found_tlds:
                            found_tlds.append(tld)
                            logger.info(f"  -> Found: annas-archive.{tld}")
            
            if found_tlds:
                logger.info(f"Found {len(found_tlds)} domains from Wikipedia")
            return found_tlds
    except Exception as e:
        logger.error(f"Wikipedia failed: {e}")
    
    return []

# ------------------------------
# MAIN
# ------------------------------
async def main():
    args = parse_args()
    
    logger.info("=== AI Domain Scanner (Hybrid) ===")
    logger.info(f"Model: {MODEL_NAME}")
    logger.info("Method: curl subprocess + async AI")
    
    saved_domains = load_saved_domains()
    is_full_scan = (args.command == 'scan')
    
    if is_full_scan:
        logger.info("Mode: FULL SCAN")
        all_tlds = VALID_2CHAR_TLDS.copy()
    else:
        logger.info("Mode: NORMAL SCAN")
        
        wikipedia_tlds = await get_wikipedia_domains()
        
        saved_tlds = []
        for d in saved_domains:
            match = re.search(r'annas-archive\.([a-z]+)', d)
            if match:
                saved_tlds.append(match.group(1))
        
        # Include known working domains
        manual_tlds = ["lib", "net", "io", "cat", "co"]
        
        all_tlds = []
        for source in [wikipedia_tlds, saved_tlds, manual_tlds]:
            for tld in source:
                if tld not in all_tlds:
                    all_tlds.append(tld)
    
    logger.info(f"Total TLDs: {len(all_tlds)}")
    logger.info(f"List: {all_tlds}")
    
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    valid_links = []
    
    async with aiohttp.ClientSession() as session:
        tasks = [check_domain(session, semaphore, tld) for tld in all_tlds]
        
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            result = await coro
            if result:
                if not domain_exists(result):
                    append_domain(result)
                valid_links.append(result)
            
            if (i + 1) % 10 == 0:
                logger.info(f"Progress: {i+1}/{len(all_tlds)} | Found: {len(valid_links)}")
            
            await asyncio.sleep(0.2)
    
    logger.info("\n" + "="*50)
    logger.info(f"WORKING DOMAINS: {len(valid_links)}")
    for link in valid_links:
        logger.info(f"✅ {link}")
    logger.info("="*50)

if __name__ == "__main__":
    if not hasattr(secret, 'API_KEY') or "your-actual" in secret.API_KEY:
        logger.error("Set API_KEY in secret.py!")
    else:
        asyncio.run(main())
