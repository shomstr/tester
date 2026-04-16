import socket
import time
import requests
import re
import logging
import os

logger = logging.getLogger(__name__)

def check_tcp_ping(host, port, timeout=3):
    """Checks TCP connectivity and returns latency in ms, or None if failed."""
    start_time = time.time()
    try:
        # Resolve hostname if needed
        sock = socket.create_connection((host, port), timeout=timeout)
        end_time = time.time()
        sock.close()
        return (end_time - start_time) * 1000
    except Exception as e:
        # logger.debug(f"Ping failed for {host}:{port}: {e}")
        return None

def parse_vless_host_port(link):
    """Extracts host and port from vless:// link."""
    # Match: vless://[uuid]@[host]:[port][...]
    pattern = r'vless://[^@]+@([^:?#\s/]+):(\d+)'
    match = re.search(pattern, link)
    if match:
        return match.group(1), int(match.group(2))
    return None, None

import concurrent.futures

def update_server_garant_link(local_only=False):
    """Fetches links from GitHub, tests them in parallel, and returns the best one.
    If GARANT_API_URL is set and local_only is False, fetches from the external API (laptop) instead."""
    
    if not local_only:
        api_url = os.getenv("GARANT_API_URL")
        if api_url:
            logger.info(f"Fetching Server Garant link from laptop API: {api_url}")
            try:
                target_url = api_url if api_url.endswith('/') else api_url + '/'
                response = requests.get(target_url, timeout=15)
                response.raise_for_status()
                data = response.json()
                if "link" in data and data["link"]:
                    return data["link"]
                else:
                    logger.warning(f"Invalid response from laptop API: {response.text}")
                    return None
            except Exception as e:
                logger.error(f"Failed to fetch from laptop API: {e}", exc_info=True)
                return None

    url = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
    logger.info(f"Updating Server Garant link (Parallel)...")
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        content = response.text
        lines = [line.strip() for line in content.splitlines() if line.startswith('vless://')]
        
        if not lines:
            return None

        def test_link(link):
            host, port = parse_vless_host_port(link)
            if not host or not port:
                return None, 999999
            ping = check_tcp_ping(host, port, timeout=2)
            if ping is not None:
                return link, ping
            return None, 999999

        best_link = None
        min_ping = 999999
        working_count = 0
        
        # Parallel test with max 50 workers
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(test_link, lines))
            
        for link, ping in results:
            if link:
                working_count += 1
                if ping < min_ping:
                    min_ping = ping
                    clean_link = link.split('#')[0]
                    update_time = time.strftime("%H:%M")
                    best_link = f"{clean_link}#🛡️ Обход Гарант | {update_time}"
        
        if best_link:
            logger.info(f"Parallel update finished. Tested: {len(lines)}, Working: {working_count}, Best: {min_ping:.0f}ms")
        else:
            logger.warning(f"No working links found out of {len(lines)} tested.")
            
        return best_link
        
    except Exception as e:
        logger.error(f"Failed parallel update: {e}", exc_info=True)
        return None
        
    except Exception as e:
        logger.error(f"Failed to update Server Garant link: {e}", exc_info=True)
        return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    best = update_server_garant_link(local_only=True)
    print(f"Best link: {best}")
