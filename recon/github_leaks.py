import requests
from typing import List, Dict, Tuple, Optional
from core.config import settings

def scan_github_leaks(domain: str, token: Optional[str] = None) -> Tuple[List[Dict[str, str]], Optional[str]]:
    """
    Queries GitHub API for potential sensitive credential leaks related to the domain,
    applying strict path/extension inclusion and repository noise filtering.
    """
    api_token = token or settings.GITHUB_TOKEN
    if not api_token:
        return [], "GitHub API PAT token missing. Public code leak scanning skipped."

    try:
        query = f'"{domain}" secret OR password OR api_key'
        url = f"https://api.github.com/search/code?q={query}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "EASM-Sentinel/1.0",
            "Authorization": f"Bearer {api_token}"
        }

        response = requests.get(url, headers=headers, timeout=settings.REQUEST_TIMEOUT)

        if response.status_code == 200:
            items = response.json().get("items", [])
            filtered_leaks = []

            for item in items:
                file_name = item.get("name", "").lower()
                repo_name = item.get("repository", {}).get("full_name", "").lower()

                # Filter out known noise repos
                if any(noise in repo_name for noise in settings.GITHUB_NOISE_REPOS):
                    continue

                # Enforce high-value extension filter (.env, .config, .yml)
                if file_name.endswith(settings.GITHUB_HIGH_VALUE_EXTS):
                    filtered_leaks.append({
                        "repo": item.get("repository", {}).get("full_name", "Unknown Repo"),
                        "file": item.get("name", "Unknown File"),
                        "url": item.get("html_url", "#"),
                        "path": item.get("path", "")
                    })

            return filtered_leaks[:5], None

        elif response.status_code == 401:
            return [], "GitHub API Error 401: Unauthorized access token."
        elif response.status_code == 403:
            return [], "GitHub API Rate Limit Exceeded (403). Try again later."
        else:
            return [], f"GitHub API Error: {response.status_code}"

    except requests.exceptions.RequestException as e:
        return [], f"GitHub network query failed: {str(e)}"
