import streamlit as st
import requests
import time
from langchain_ollama import OllamaLLM

# --- 1. Deterministic OSINT Workers ---

def fetch_subdomains(domain):
    """Scrapes HackerTarget for known subdomains and their IP addresses."""
    subdomains = []
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            for line in lines:
                if ',' in line:
                    sub_name, ip = line.split(',', 1)
                    subdomains.append(f"{sub_name} (IP: {ip})")
        return subdomains[:15]
    except Exception as e:
        return []

def fetch_github_leaks(domain, token):
    """Searches GitHub and filters out both bad extensions AND known noise repositories."""
    leaks = []
    if not token:
        return ["⚠️ Please enter a GitHub API Token in the sidebar to enable scanning."]
        
    try:
        query = f'"{domain}" secret OR password OR api_key'
        url = f"https://api.github.com/search/code?q={query}"
        
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "EASM-OSINT-Tool",
            "Authorization": f"Bearer {token}"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            items = response.json().get('items', [])
            if not items:
                return ["✅ No obvious GitHub leaks found."]
                
            high_value_extensions = ['.env', '.yml', '.yaml', '.json', '.config', '.ini']
            
            # THE NEW FILTER: Ignore known public API documentation and test repos
            noise_repos = ['apis-guru', 'openapi', 'swagger', 'postman', 'apideck']
            
            filtered_items = []
            
            for item in items:
                file_name = item['name'].lower()
                repo_name = item['repository']['full_name'].lower()
                
                # Check if it's in a noisy repository
                if any(noise in repo_name for noise in noise_repos):
                    continue # Skip this file completely
                    
                # Check if it has a good extension
                if any(file_name.endswith(ext) for ext in high_value_extensions):
                    filtered_items.append(item)
            
            if not filtered_items:
                return ["✅ Leaks found, but were filtered out as public documentation/noise."]
                
            for item in filtered_items[:5]: 
                repo_name = item['repository']['full_name']
                file_name = item['name']
                html_url = item['html_url']
                leaks.append(f"📦 **Repo:** {repo_name} | **File:** {file_name}\n\n🔗 [View File]({html_url})")
            return leaks
            
        elif response.status_code == 422:
            return ["⚠️ GitHub API Error 422: Search query syntax was rejected."]
        elif response.status_code == 401:
            return ["⚠️ Invalid GitHub Token. (Error 401)"]
        elif response.status_code == 403:
            return ["⚠️ GitHub API Rate Limit Reached. Try again in a minute."]
        else:
            return [f"GitHub API Error: {response.status_code}"]
            
    except Exception as e:
        return [f"Network Error: {e}"]
def fetch_threat_intel(domain):
    """Queries AlienVault OTX and filters out low-level phishing noise."""
    intel = []
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            
            if not pulses:
                return ["✅ No active threat campaigns found for this domain."]
            
            # THE FILTER: Words we DON'T care about for infrastructure scanning
            noise_tags = ['phishing', 'spam', 'malware', 'scam']
            filtered_pulses = []
            
            for pulse in pulses:
                tags = [str(t).lower() for t in pulse.get("tags", [])]
                # If the pulse is just a phishing link, skip it
                if any(noise in tags for noise in noise_tags):
                    continue
                filtered_pulses.append(pulse)
                
            # If everything was filtered out
            if not filtered_pulses:
                 return ["✅ Threat pulses exist, but were filtered out as low-level phishing noise."]
                 
            # Grab the top 5 legitimate infrastructure threats
            for pulse in filtered_pulses[:5]:
                name = pulse.get("name", "Unknown Threat")
                tags = ", ".join(pulse.get("tags", [])) if pulse.get("tags") else "None"
                intel.append(f"🚨 **Campaign:** {name}\n\n🏷️ **Tags:** {tags}\n\n---")
                
            return intel
        else:
            return [f"Threat Intel API Error: {response.status_code}"]
    except Exception as e:
        return [f"Network Error: {e}"]

# --- 2. The AI Analyst ---
def generate_ai_briefing(domain, subdomains, github_leaks, threat_intel):
    """Passes all OSINT data to the local Phi-3 model."""
    llm = OllamaLLM(model="phi3")
    
    prompt = f"""
    You are an elite Cyber Threat Intelligence Analyst. 
    Write a concise, 3-paragraph executive threat briefing for {domain}.
    
    Raw Intelligence:
    - Subdomains Found: {', '.join(subdomains)}
    - GitHub Exposures Found: {len(github_leaks)} potential credential leaks.
    - AlienVault Threat Intel: {len(threat_intel)} associated malicious campaigns.
    
    Synthesize this data. Explain the combined risk of external infrastructure exposure, source code leaks, and any associated threat actor campaigns. Do not make up fake vulnerabilities.
    """
    return llm.stream(prompt)

# --- 3. Streamlit Web Dashboard ---
st.set_page_config(page_title="EASM Sentinel", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- UI: Sidebar ---
with st.sidebar:
    st.header("⚙️ Tool Settings")
    st.markdown("Enter your API keys below. They are not saved or stored anywhere.")
    github_token = st.text_input("GitHub API Token", type="password")

# --- UI: Main Page ---
st.title("🛡️ EASM Dashboard")
st.markdown("**AI Threat Intelligence Platform**")
st.markdown("---")

target_domain = st.text_input("Enter Target Domain (e.g., tesla.com):")

if st.button("Initiate Reconnaissance"):
    if target_domain:
        # We now have 4 Tabs!
        tab1, tab2, tab3, tab4 = st.tabs(["📡 Network", "💻 Code Leaks", "🏴‍☠️ Threat Intel", "🧠 AI Briefing"])
        
        with tab1:
            st.subheader(f"Infrastructure: {target_domain}")
            with st.spinner("Mapping subdomains..."):
                subs = fetch_subdomains(target_domain)
            if subs:
                st.success(f"Found {len(subs)} subdomains!")
                for sub in subs:
                    st.code(sub)
            else:
                st.warning("No subdomains found.")

        with tab2:
            st.subheader("Public Source Code Leaks")
            with st.spinner("Scanning GitHub repositories..."):
                time.sleep(1)
                leaks = fetch_github_leaks(target_domain, github_token)
            if leaks and "⚠️" not in leaks[0] and "✅" not in leaks[0]:
                st.error(f"Found {len(leaks)} potential secrets exposed!")
                for leak in leaks:
                    st.info(leak)
            elif leaks:
                st.warning(leaks[0])
                
        with tab3:
            st.subheader("AlienVvault OTX Threat Indicators")
            with st.spinner("Querying AlienVvault..."):
                time.sleep(1)
                intel = fetch_threat_intel(target_domain)
            if intel and "✅" not in intel[0] and "⚠️" not in intel[0]:
                st.error(f"Found {len(intel)} threat indicators!")
                for i in intel:
                    st.warning(i)
            elif intel:
                st.success(intel[0])

        with tab4:
            st.subheader("Local AI Threat Briefing")
            with st.spinner("Phi-3 is drafting the executive summary..."):
                st.write_stream(generate_ai_briefing(target_domain, subs, leaks, intel))
    else:
        st.error("Please enter a domain.")
