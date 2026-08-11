import os
import streamlit as st
from dataclasses import dataclass

def get_secret(key: str, default: str = "") -> str:
    try:
        if key in st.secrets:
            return str(st.secrets[key])
    except Exception:
        pass
    return os.getenv(key, default)

@dataclass(frozen=True)
class Config:
    REQUEST_TIMEOUT: int = int(get_secret("EASM_TIMEOUT", "8"))
    MAX_WORKERS: int = int(get_secret("EASM_MAX_WORKERS", "5"))
    
    # AWS Bedrock Settings (Defaulting to Meta Llama 3.1 8B)
    AWS_REGION: str = get_secret("AWS_REGION", "us-east-1")
    AWS_ACCESS_KEY_ID: str = get_secret("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = get_secret("AWS_SECRET_ACCESS_KEY", "")
    BEDROCK_MODEL_ID: str = get_secret("BEDROCK_MODEL_ID", "us.meta.llama3-1-8b-instruct-v1:0")
    
    # External Recon Keys
    GITHUB_TOKEN: str = get_secret("GITHUB_TOKEN", "")
    SHODAN_API_KEY: str = get_secret("SHODAN_API_KEY", "")
    
    GITHUB_HIGH_VALUE_EXTS: tuple = ('.env', '.yml', '.yaml', '.json', '.config', '.ini')
    GITHUB_NOISE_REPOS: tuple = ('apis-guru', 'openapi', 'swagger', 'postman', 'apideck')

settings = Config()
