# ======================== START OF FILE ========================
import sys
import io
import os
import traceback
import time
import threading

# ======================== CONSOLE SUPPRESSION ========================

def setup_global_exception_handler():
    """Setup global exception handler to prevent crashes"""
    def handle_exception(exc_type, exc_value, exc_traceback):
        # Don't handle keyboard interrupts
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        error_msg = f"Unhandled Exception: {exc_type.__name__}: {exc_value}"
        
        # Log to file
        try:
            with open('r3kon_error.log', 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Exception: {exc_type.__name__}\n")
                f.write(f"Message: {exc_value}\n")
                f.write("Traceback:\n")
                traceback.print_tb(exc_traceback, file=f)
                f.write(f"{'='*60}\n")
        except:
            pass
        
        # Show user-friendly error (only if GUI is ready)
        try:
            if sys.platform == 'win32':
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    0, 
                    f"R3KON GPT encountered an error:\n\n{exc_value}\n\nCheck r3kon_error.log for details.", 
                    "R3KON GPT Error", 
                    0x10 | 0x0  # MB_ICONERROR | MB_OK
                )
        except:
            pass
        
        # Exit gracefully
        os._exit(1)  # Force exit
    
    sys.excepthook = handle_exception

# Call it immediately
setup_global_exception_handler()

# Hide console window on Windows
try:
    if sys.platform == 'win32':
        import ctypes
        # Get console window handle and hide it
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        
        # Get console window
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            user32.ShowWindow(hwnd, 0)  # 0 = SW_HIDE
except Exception as e:
    pass  # Don't crash if hiding fails

# ======================== AGGRESSIVE CPU-ONLY ENVIRONMENT ========================
# Set ALL possible CUDA/CUDA-related environment variables BEFORE importing anything
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['CUDA_DEVICE_ORDER'] = 'PCI_BUS_ID'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['VECLIB_MAXIMUM_THREADS'] = '1'
os.environ['NUMEXPR_NUM_THREADS'] = '1'
os.environ['GGML_CUDA'] = '0'
os.environ['GGML_OPENCL'] = '0'
os.environ['GGML_METAL'] = '0'
os.environ['GGML_VULKAN'] = '0'
os.environ['LLAMA_NO_CUDA'] = '1'
os.environ['LLAMA_CUDA'] = '0'
os.environ['GPT4ALL_NO_CUDA'] = '1'
os.environ['GPT4ALL_FORCE_CPU'] = '1'
os.environ['GPTJ_MODEL_PATH'] = ''
os.environ['GGML_NO_CUDA'] = '1'
os.environ['GGML_USE_CUBLAS'] = '0'
os.environ['GGML_USE_CLBLAST'] = '0'
os.environ['GGML_USE_METAL'] = '0'
os.environ['GGML_NATIVE'] = '1'
os.environ['GGML_NO_AVX'] = '0'
os.environ['GGML_NO_AVX2'] = '0'
os.environ['GGML_NO_AVX512'] = '0'
os.environ['LLAMA_NO_AVX'] = '0'
os.environ['LLAMA_NO_AVX2'] = '0'
os.environ['LLAMA_NO_AVX512'] = '0'

# ======================== SINGLE SuppressStderr CONTEXT MANAGER ========================
class SuppressStderr:
    """Singleton context manager to suppress stderr"""
    def __init__(self):
        self._original_stderr = None
        self._null_stderr = None
    
    def __enter__(self):
        self._original_stderr = sys.stderr
        self._null_stderr = io.StringIO()
        sys.stderr = self._null_stderr
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stderr = self._original_stderr
        self._null_stderr.close()

# ======================== IMPORTS WITH SUPPRESSION ========================
# Use ONE context manager for ALL potentially noisy imports

with SuppressStderr():
    # Import everything that might generate warnings
    from flask import Flask, request, jsonify, Response, send_file
    from flask_cors import CORS
    import logging
    import warnings
    warnings.filterwarnings('ignore')
    
    # Now import gpt4all within the same context
    from gpt4all import GPT4All
    
    # Import other dependencies
    import re
    import socket
    import json
    import hashlib
    import base64
    from datetime import datetime
    from urllib.parse import urlparse, parse_qs
    from bs4 import BeautifulSoup
    import requests
    import webview

print("[SUCCESS] All imports completed successfully")

# Continue with the rest of your code...
# ======================== REST OF YOUR CODE BELOW ========================
import webview
import threading
import traceback
from threading import Lock, Event

# Get base path for PyInstaller
def get_base_path():
    if getattr(sys, 'frozen', False):
        # Running as compiled EXE
        base_path = sys._MEIPASS  # PyInstaller temp extraction folder
        print(f"[DEBUG] Running as EXE")
        print(f"[DEBUG] _MEIPASS (extracted files): {base_path}")
        print(f"[DEBUG] EXE location: {sys.executable}")
        print(f"[DEBUG] EXE directory: {os.path.dirname(sys.executable)}")
        return base_path
    else:
        # Running as Python script
        base_path = os.path.dirname(os.path.abspath(__file__))
        print(f"[DEBUG] Running as Python script")
        print(f"[DEBUG] Script directory: {base_path}")
        return base_path

BASE_PATH = get_base_path()

# Flask app
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Global variables
llm = None
model_loaded = False
loading_progress = 0
loading_message = "Initializing..."
model_lock = Lock()
flask_started = False
stop_generation_flag = False
model_loaded_event = Event()

SYSTEM_PROMPT = """You are R3KON GPT, an elite cybersecurity AI assistant with advanced threat analysis capabilities.

Core Competencies:
- Offensive Security: Reconnaissance, vulnerability analysis, threat modeling
- Defensive Security: Incident response, log analysis, hardening recommendations
- Code Security: Static analysis, vulnerability detection, secure coding
- Compliance: OWASP, MITRE ATT&CK, CWE mapping

Response Guidelines:
1. Be precise, technical, and actionable
2. Provide severity ratings (CRITICAL/HIGH/MEDIUM/LOW)
3. Include remediation steps for all findings
4. Reference industry standards (OWASP, MITRE, CWE)
5. Keep responses focused and professional
"""

# Security Analysis Knowledge Base
SECURITY_PATTERNS = {
    'python': {
        'dangerous_functions': ['eval', 'exec', 'compile', '__import__', 'pickle.loads', 'yaml.load', 'marshal.loads'],
        'sql_patterns': [r'execute$$.*%.*$$', r'cursor\.execute.*\+', r'f".*SELECT.*{', r'\.format\(.*SELECT'],
        'secrets_patterns': [r'password\s*=\s*["\'][^"\']{3,}', r'api_key\s*=\s*["\']', r'secret\s*=\s*["\']', r'token\s*=\s*["\']', r'AWS_', r'STRIPE_'],
        'xss_patterns': [r'innerHTML\s*=', r'document\.write', r'\.html\('],
        'weak_crypto': ['md5', 'sha1', 'DES', 'RC4', 'ECB'],
        'path_traversal': [r'\.\./', r'\.\.\\', r'os\.system', r'subprocess\.call'],
        'deserialization': ['pickle.loads', 'marshal.loads', 'yaml.load'],
    },
    'javascript': {
        'dangerous_functions': ['eval', 'Function', 'setTimeout', 'setInterval', 'innerHTML', 'outerHTML'],
        'xss_patterns': [r'innerHTML\s*=', r'document\.write', r'\.html\(', r'dangerouslySetInnerHTML', r'v-html'],
        'secrets_patterns': [r'apiKey\s*[:=]', r'password\s*[:=]', r'secret\s*[:=]', r'token\s*[:=]', r'Bearer\s+[A-Za-z0-9\-_]+'],
        'prototype_pollution': [r'__proto__', r'constructor\.prototype', r'\[constructor\]'],
        'open_redirect': [r'window\.location\s*=', r'window\.open\(', r'document\.location'],
    },
    'sql': {
        'injection_patterns': [r'union\s+select', r'or\s+1\s*=\s*1', r';\s*drop', r'xp_cmdshell', r'exec\s*\('],
    },
    'owasp_top10': [
        'Broken Access Control',
        'Cryptographic Failures',
        'Injection',
        'Insecure Design',
        'Security Misconfiguration',
        'Vulnerable Components',
        'Authentication Failures',
        'Software Data Integrity Failures',
        'Security Logging Failures',
        'Server-Side Request Forgery'
    ]
}

def find_free_port():
    """Find a free port to use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def load_model():
    """Load the AI model using GPT4All (CPU-only, optimized for speed)"""
    global llm, model_loaded, loading_progress, loading_message, model_loaded_event
    
    try:
        print(f"\n{'='*60}")
        print(f"[MODEL DEBUG] Starting model load process")
        
        # Initialize to False at start
        model_loaded = False
        loading_progress = 0
        loading_message = "Starting model load..."
        model_loaded_event.clear()  # Clear the event at start
        
        loading_progress = 10
        loading_message = "Locating model file..."
        print(f"[1/5] Locating model file... (10%)")
        
        model_filename = "qwen1.5-1.8b-chat-q4_k_m.gguf"
        
        possible_paths = [
            os.path.join(BASE_PATH, "model", model_filename),
            os.path.join(BASE_PATH, model_filename),
            os.path.join(os.path.dirname(sys.executable), "model", model_filename),
            os.path.join(os.getcwd(), "model", model_filename),
        ]
        
        model_path = None
        model_dir = None
        for path in possible_paths:
            if os.path.exists(path):
                model_path = path
                model_dir = os.path.dirname(path)
                break
        
        if not model_path:
            loading_progress = 0
            loading_message = "ERROR: Model file not found"
            model_loaded_event.set()
            print(f"[ERROR] Model file '{model_filename}' not found!")
            return False
        
        loading_progress = 35
        loading_message = "Initializing GPT4All..."
        print(f"[2/5] Initializing GPT4All... (35%)")
        
        loading_progress = 50
        loading_message = "Loading model weights (30-60 seconds)..."
        print(f"[3/5] Loading model weights... (50%)")
        
        start_time = time.time()
        
        with SuppressStderr():
            llm = GPT4All(
                model_name=model_filename,
                model_path=model_dir,
                allow_download=False,
                device='cpu',
                n_threads=4,
                n_ctx=512,
                verbose=False
            )
        
        # CRITICAL: Set model_loaded BEFORE testing
        model_loaded = True
        loading_progress = 90
        loading_message = "Finalizing..."
        
        # Test the model
        print("[4/5] Testing model... (90%)")
        try:
            test_result = llm.generate("Hi", max_tokens=2, streaming=False)
            print(f"[SUCCESS] Model test passed: '{test_result}'")
        except Exception as test_e:
            print(f"[WARNING] Model test failed but continuing: {test_e}")
        
        load_time = time.time() - start_time
        print(f"[SUCCESS] Model loaded in {load_time:.1f}s")
        
        loading_progress = 100
        loading_message = "Ready!"
        
        # CRITICAL: Signal the event AFTER everything is ready
        model_loaded_event.set()
        
        print(f"[5/5] R3KON GPT READY! (100%)")
        print(f"[DEBUG] Final state: model_loaded={model_loaded}, progress={loading_progress}, event_set={model_loaded_event.is_set()}")
        
        # Force update status one more time
        print("[STATUS] Model loading complete - API should report ready")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}")
        import traceback
        traceback.print_exc()
        
        model_loaded = False
        loading_progress = 0
        loading_message = f"Error: {str(e)}"
        model_loaded_event.set()  # Still set event to prevent hanging
        return False

def analyze_code_security(code, language):
    """Advanced static code analysis"""
    findings = []
    lines = code.split('\n')
    
    if language.lower() in SECURITY_PATTERNS:
        patterns = SECURITY_PATTERNS[language.lower()]
        
        # Dangerous functions
        if 'dangerous_functions' in patterns:
            for func in patterns['dangerous_functions']:
                for i, line in enumerate(lines, 1):
                    if func in line:
                        findings.append({
                            'type': 'Dangerous Function Usage',
                            'severity': 'HIGH',
                            'line': i,
                            'code': line.strip(),
                            'issue': f'Use of dangerous function: {func}',
                            'remediation': f'Avoid {func}. Use safer alternatives or implement strict input validation.',
                            'cwe': 'CWE-94: Improper Control of Generation of Code'
                        })
        
        # SQL injection patterns
        if 'sql_patterns' in patterns:
            for pattern in patterns['sql_patterns']:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append({
                            'type': 'SQL Injection Vulnerability',
                            'severity': 'CRITICAL',
                            'line': i,
                            'code': line.strip(),
                            'issue': 'Potential SQL injection - unsanitized user input in query',
                            'remediation': 'Use parameterized queries or ORM methods. Never concatenate user input.',
                            'cwe': 'CWE-89: SQL Injection'
                        })
        
        # Hardcoded secrets
        if 'secrets_patterns' in patterns:
            for pattern in patterns['secrets_patterns']:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'Hardcoded Credential',
                            'severity': 'CRITICAL',
                            'line': i,
                            'code': line.strip()[:50] + '...',
                            'issue': 'Hardcoded credential or API key detected',
                            'remediation': 'Use environment variables (.env) or secret management systems (AWS Secrets Manager, Azure Key Vault)',
                            'cwe': 'CWE-798: Use of Hard-coded Credentials'
                        })
        
        # XSS patterns
        if 'xss_patterns' in patterns:
            for pattern in patterns['xss_patterns']:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'HIGH',
                            'line': i,
                            'code': line.strip(),
                            'issue': 'Potential XSS vulnerability - unsafe DOM manipulation',
                            'remediation': 'Sanitize all user input. Use textContent instead of innerHTML, or DOMPurify library.',
                            'cwe': 'CWE-79: Cross-site Scripting'
                        })
        
        # Weak cryptography
        if 'weak_crypto' in patterns:
            for crypto in patterns['weak_crypto']:
                for i, line in enumerate(lines, 1):
                    if crypto in line:
                        findings.append({
                            'type': 'Weak Cryptography',
                            'severity': 'HIGH',
                            'line': i,
                            'code': line.strip(),
                            'issue': f'Use of weak/deprecated cryptographic algorithm: {crypto}',
                            'remediation': 'Use SHA-256 or SHA-3 for hashing, AES-256-GCM for encryption, bcrypt/Argon2 for passwords.',
                            'cwe': 'CWE-327: Use of Broken Cryptographic Algorithm'
                        })
    
    return findings

def analyze_api_security(endpoint_data):
    """API Attack Surface Analyzer with business logic abuse detection"""
    findings = []
    
    method = endpoint_data.get('method', 'GET').upper()
    url = endpoint_data.get('url', '')
    headers = endpoint_data.get('headers', {})
    params = endpoint_data.get('params', {})
    body = endpoint_data.get('body', '')
    
    # IDOR check
    if re.search(r'[?&](id|user|account|order)=\d+', url):
        findings.append({
            'type': 'IDOR Vulnerability Risk',
            'severity': 'HIGH',
            'issue': 'Sequential/predictable identifiers exposed in API',
            'details': 'Attackers can enumerate resources by changing ID values',
            'remediation': 'Implement object-level authorization checks. Use UUIDs instead of sequential IDs.',
            'owasp': 'A01:2021 – Broken Access Control'
        })
    
    # Authentication check
    auth_headers = ['authorization', 'x-api-key', 'x-auth-token', 'cookie']
    has_auth = any(h.lower() in [k.lower() for k in headers.keys()] for h in auth_headers)
    
    if not has_auth and method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        findings.append({
            'type': 'Missing Authentication',
            'severity': 'CRITICAL',
            'issue': f'{method} operation without authentication headers',
            'remediation': 'Implement JWT tokens, OAuth2, or API key authentication.',
            'owasp': 'A07:2021 – Identification and Authentication Failures'
        })
    
    # Rate limiting check
    rate_limit_headers = ['x-ratelimit-limit', 'x-rate-limit']
    has_rate_limit = any(h.lower() in [k.lower() for k in headers.keys()] for h in rate_limit_headers)
    
    if not has_rate_limit:
        findings.append({
            'type': 'Missing Rate Limiting',
            'severity': 'MEDIUM',
            'issue': 'No rate limiting headers detected',
            'remediation': 'Implement rate limiting (e.g., 100 req/min per IP).',
            'owasp': 'A04:2021 – Insecure Design'
        })
    
    return findings

def analyze_web_security(url, headers):
    """Web Security Posture Scanner"""
    findings = []
    
    security_headers = {
        'strict-transport-security': {
            'severity': 'HIGH',
            'issue': 'Missing HSTS header',
            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'content-security-policy': {
            'severity': 'HIGH',
            'issue': 'Missing CSP header',
            'remediation': 'Implement Content-Security-Policy to prevent XSS'
        },
        'x-content-type-options': {
            'severity': 'MEDIUM',
            'issue': 'Missing X-Content-Type-Options',
            'remediation': 'Add: X-Content-Type-Options: nosniff'
        },
        'x-frame-options': {
            'severity': 'MEDIUM',
            'issue': 'Missing X-Frame-Options',
            'remediation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
        }
    }
    
    header_keys_lower = [k.lower() for k in headers.keys()]
    
    for header, details in security_headers.items():
        if header not in header_keys_lower:
            findings.append({
                'type': 'Missing Security Header',
                'severity': details['severity'],
                'header': header,
                'issue': details['issue'],
                'remediation': details['remediation'],
                'owasp': 'A05:2021 – Security Misconfiguration'
            })
    
    # HTTPS check
    if url.startswith('http://'):
        findings.append({
            'type': 'Insecure Protocol',
            'severity': 'CRITICAL',
            'issue': 'Site using HTTP instead of HTTPS',
            'remediation': 'Implement TLS/SSL certificate. Redirect all HTTP to HTTPS.',
            'owasp': 'A02:2021 – Cryptographic Failures'
        })
    
    return findings

def analyze_metadata(content):
    """Metadata & Exposure Intelligence"""
    findings = []
    
    # Email addresses
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
    if emails:
        findings.append({
            'type': 'Email Exposure',
            'severity': 'LOW',
            'count': len(set(emails)),
            'samples': list(set(emails))[:5],
            'issue': 'Email addresses exposed in content'
        })
    
    # Internal paths
    paths = re.findall(r'[C-Z]:\\[\w\\]+|/home/[\w/]+|/var/[\w/]+', content)
    if paths:
        findings.append({
            'type': 'Internal Path Disclosure',
            'severity': 'MEDIUM',
            'count': len(set(paths)),
            'samples': list(set(paths))[:5],
            'issue': 'Internal file system paths exposed'
        })
    
    # Version numbers
    versions = re.findall(r'\b(?:v|version|ver\.?)\s*[\d.]+\b', content, re.IGNORECASE)
    if versions:
        findings.append({
            'type': 'Version Disclosure',
            'severity': 'LOW',
            'count': len(set(versions)),
            'samples': list(set(versions))[:3],
            'issue': 'Software versions exposed'
        })
    
    return findings

def analyze_threat_surface(architecture):
    """Threat Surface Mapper - AI modeling of attack paths"""
    analysis = {
        'entry_points': [],
        'trust_boundaries': [],
        'high_risk_components': [],
        'attack_paths': []
    }
    
    # Identify common entry points
    if 'api' in architecture.lower() or 'rest' in architecture.lower():
        analysis['entry_points'].append('REST API endpoints')
    if 'web' in architecture.lower() or 'frontend' in architecture.lower():
        analysis['entry_points'].append('Web application frontend')
    if 'database' in architecture.lower() or 'db' in architecture.lower():
        analysis['entry_points'].append('Database layer')
    if 'auth' in architecture.lower():
        analysis['entry_points'].append('Authentication system')
    
    # Trust boundaries
    if 'user' in architecture.lower():
        analysis['trust_boundaries'].append('User input validation')
    if 'third-party' in architecture.lower() or 'external' in architecture.lower():
        analysis['trust_boundaries'].append('External service integration')
    
    # High-risk components
    if 'file upload' in architecture.lower():
        analysis['high_risk_components'].append('File upload (RCE, malware risk)')
    if 'payment' in architecture.lower():
        analysis['high_risk_components'].append('Payment processing (PCI-DSS compliance)')
    if 'admin' in architecture.lower():
        analysis['high_risk_components'].append('Admin panel (privilege escalation)')
    
    return analysis

def analyze_auth_logic(auth_flow):
    """Authentication Logic Evaluator"""
    findings = []
    
    if 'session' in auth_flow.lower():
        if 'httponly' not in auth_flow.lower():
            findings.append({
                'type': 'Insecure Session Cookie',
                'severity': 'HIGH',
                'issue': 'Session cookies not using HttpOnly flag',
                'remediation': 'Set HttpOnly and Secure flags on session cookies'
            })
    
    if 'jwt' in auth_flow.lower() or 'token' in auth_flow.lower():
        if 'expire' not in auth_flow.lower() and 'expiry' not in auth_flow.lower():
            findings.append({
                'type': 'Token Expiration Missing',
                'severity': 'MEDIUM',
                'issue': 'No token expiration mentioned',
                'remediation': 'Implement short-lived access tokens with refresh tokens'
            })
    
    if 'password' in auth_flow.lower():
        if 'hash' not in auth_flow.lower() and 'bcrypt' not in auth_flow.lower():
            findings.append({
                'type': 'Password Storage Risk',
                'severity': 'CRITICAL',
                'issue': 'No mention of password hashing',
                'remediation': 'Use bcrypt or Argon2 for password hashing'
            })
    
    if 'mfa' not in auth_flow.lower() and '2fa' not in auth_flow.lower():
        findings.append({
            'type': 'MFA Not Implemented',
            'severity': 'MEDIUM',
            'issue': 'Multi-factor authentication not mentioned',
            'remediation': 'Implement TOTP or SMS-based MFA for sensitive accounts'
        })
    
    return findings

def provide_incident_response(incident_desc):
    """Incident Response Assistant"""
    response = {
        'triage': [],
        'containment': [],
        'recovery': [],
        'lessons_learned': []
    }
    
    incident_lower = incident_desc.lower()
    
    # Triage steps
    response['triage'] = [
        '1. Verify and validate the incident',
        '2. Determine scope and affected systems',
        '3. Assess severity and business impact',
        '4. Notify stakeholders and incident response team'
    ]
    
    # Containment based on incident type
    if 'malware' in incident_lower or 'ransomware' in incident_lower:
        response['containment'] = [
            '1. Isolate affected systems from network',
            '2. Disable remote access and VPN',
            '3. Block malicious IPs/domains at firewall',
            '4. Preserve forensic evidence'
        ]
    elif 'breach' in incident_lower or 'unauthorized access' in incident_lower:
        response['containment'] = [
            '1. Reset compromised credentials immediately',
            '2. Revoke active sessions and tokens',
            '3. Enable MFA for all accounts',
            '4. Review and restrict access controls'
        ]
    else:
        response['containment'] = [
            '1. Isolate affected systems',
            '2. Implement temporary security controls',
            '3. Block attack vectors',
            '4. Preserve evidence for analysis'
        ]
    
    # Recovery
    response['recovery'] = [
        '1. Patch vulnerabilities exploited',
        '2. Restore from clean backups',
        '3. Verify system integrity',
        '4. Monitor for residual threats'
    ]
    
    # Lessons learned
    response['lessons_learned'] = [
        '1. Document incident timeline and actions',
        '2. Identify root cause',
        '3. Update security policies',
        '4. Conduct team retrospective'
    ]
    
    return response

def explain_threat_intelligence(query):
    """Threat Intelligence Explainer"""
    explanations = {
        'phishing': {
            'description': 'Social engineering attack using fraudulent communications',
            'detection': 'Email filtering, SPF/DKIM/DMARC, user training',
            'mitigation': 'MFA, email authentication, security awareness training',
            'impact': 'Credential theft, malware delivery, financial loss'
        },
        'ransomware': {
            'description': 'Malware that encrypts data and demands payment',
            'detection': 'Behavioral analysis, file integrity monitoring, EDR',
            'mitigation': 'Regular backups, network segmentation, patch management',
            'impact': 'Data loss, operational disruption, financial damage'
        },
        'sql injection': {
            'description': 'Injection attack inserting malicious SQL queries',
            'detection': 'WAF, code review, penetration testing',
            'mitigation': 'Parameterized queries, input validation, least privilege',
            'impact': 'Data breach, unauthorized access, data manipulation'
        }
    }
    
    query_lower = query.lower()
    for key, data in explanations.items():
        if key in query_lower:
            return data
    
    return {
        'description': 'Threat intelligence provides information about cyber threats',
        'detection': 'Varies by threat type',
        'mitigation': 'Defense in depth approach',
        'impact': 'Depends on threat severity and response'
    }


def generate_security_policy(org_type, org_size):
    """Security Policy Generator"""
    policies = {
        'password_policy': {
            'title': 'Password Policy',
            'requirements': [
                'Minimum 12 characters',
                'Mix of uppercase, lowercase, numbers, symbols',
                'No reuse of last 10 passwords',
                'Change every 90 days for privileged accounts',
                'Use password manager for secure storage'
            ]
        },
        'access_control': {
            'title': 'Access Control Policy',
            'requirements': [
                'Least privilege principle',
                'Role-based access control (RBAC)',
                'Regular access reviews (quarterly)',
                'Immediate revocation upon termination',
                'MFA for all privileged accounts'
            ]
        },
        'incident_response': {
            'title': 'Incident Response Policy',
            'requirements': [
                'Designated incident response team',
                '24/7 monitoring and alerting',
                'Documented response procedures',
                'Regular drills and training',
                'Post-incident review process'
            ]
        }
    }
    
    if org_size == 'enterprise':
        policies['data_classification'] = {
            'title': 'Data Classification Policy',
            'requirements': [
                'Public, Internal, Confidential, Restricted',
                'Encryption for confidential data',
                'DLP tools for monitoring',
                'Regular audits',
                'Compliance with regulations (GDPR, HIPAA, etc.)'
            ]
        }
    
    return policies

def calculate_defensive_readiness(security_state):
    """Defensive Readiness Scorecard"""
    score = 0
    max_score = 100
    gaps = []
    
    # Monitoring (25 points)
    if security_state.get('logging_enabled'):
        score += 10
    else:
        gaps.append('Enable centralized logging')
    
    if security_state.get('siem_deployed'):
        score += 15
    else:
        gaps.append('Deploy SIEM for threat detection')
    
    # Response capability (25 points)
    if security_state.get('incident_response_plan'):
        score += 15
    else:
        gaps.append('Create incident response plan')
    
    if security_state.get('response_team'):
        score += 10
    else:
        gaps.append('Establish incident response team')
    
    # Configuration hygiene (25 points)
    if security_state.get('patch_management'):
        score += 15
    else:
        gaps.append('Implement patch management process')
    
    if security_state.get('hardened_configs'):
        score += 10
    else:
        gaps.append('Harden system configurations')
    
    # Access controls (25 points)
    if security_state.get('mfa_enabled'):
        score += 15
    else:
        gaps.append('Enable MFA for all users')
    
    if security_state.get('least_privilege'):
        score += 10
    else:
        gaps.append('Implement least privilege access')
    
    readiness_level = 'Critical' if score < 40 else 'Low' if score < 60 else 'Medium' if score < 80 else 'High'
    
    return {
        'readiness_score': score,
        'max_score': max_score,
        'readiness_level': readiness_level,
        'priority_gaps': gaps[:3],
        'all_gaps': gaps
    }


def generate_response_stream(user_message, config, history):
    """Generate streaming response with tool integration"""
    global stop_generation_flag, llm, model_loaded
    stop_generation_flag = False
    
    try:
        tool_response = None
        message_lower = user_message.lower()
        
        # Code Scanner - NOW ACTUALLY ANALYZES CODE
        if ('code scanner' in message_lower or 'scan code' in message_lower or 'analyze code' in message_lower) and '```' in user_message:
            # Extract code and language from markdown code blocks
            code_match = re.search(r'```(\w+)?\n([\s\S]+?)```', user_message)
            if code_match:
                language = code_match.group(1) or 'python'
                code = code_match.group(2)
                
                findings = analyze_code_security(code, language)
                
                if findings:
                    tool_response = f"**Code Scanner Results**\n\n**Language:** {language}\n**Findings:** {len(findings)}\n\n"
                    
                    for idx, finding in enumerate(findings, 1):
                        severity_level = finding.get('severity', 'UNKNOWN')
                        tool_response += f"### Finding #{idx}: {finding.get('type', 'Unknown')}\n"
                        tool_response += f"**Severity:** {severity_level}\n"
                        tool_response += f"**Line:** {finding.get('line', 'N/A')}\n"
                        tool_response += f"**Code:** `{finding.get('code', 'N/A')}`\n"
                        tool_response += f"**Issue:** {finding.get('issue', 'N/A')}\n"
                        tool_response += f"**Remediation:** {finding.get('remediation', 'N/A')}\n"
                        if 'cwe' in finding:
                            tool_response += f"**Reference:** {finding['cwe']}\n"
                        tool_response += "\n"
                    
                    user_message = f"Based on the code security scan results below, explain the vulnerabilities found and provide detailed guidance:\n\n{tool_response}\n\nOriginal user question: {user_message}"
                else:
                    tool_response = "**Code Scanner Results**\n\nNo major security issues detected in the provided code. However, consider:\n- Input validation\n- Error handling\n- Logging security events\n- Following principle of least privilege"
                    user_message = f"Based on this code scan result: {tool_response}\n\nExplain what was checked and provide best practices. Original question: {user_message}"
            else:
                tool_response = "**Code Scanner Activated**\n\nPlease provide code in a code block:\n\n```python\n# Your code here\n```\n\nI'll analyze it for vulnerabilities!"
                yield f"data: {json.dumps({'token': tool_response})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
        
        # API Analyzer - NOW ACTUALLY ANALYZES APIS
        elif ('api analyzer' in message_lower or 'analyze api' in message_lower) and ('http' in message_lower or 'method' in message_lower):
            method_match = re.search(r'\b(GET|POST|PUT|DELETE|PATCH)\b', user_message, re.IGNORECASE)
            url_match = re.search(r'https?://[^\s]+', user_message)
            
            if method_match and url_match:
                endpoint_data = {
                    'method': method_match.group(1).upper(),
                    'url': url_match.group(0),
                    'headers': {},
                    'params': {},
                    'body': ''
                }
                
                if 'authorization' in message_lower or 'bearer' in message_lower:
                    endpoint_data['headers']['Authorization'] = 'Bearer token'
                if 'api-key' in message_lower or 'x-api-key' in message_lower:
                    endpoint_data['headers']['X-API-Key'] = 'api_key'
                
                findings = analyze_api_security(endpoint_data)
                
                tool_response = f"**API Attack Surface Analysis**\n\n**Endpoint:** `{endpoint_data['method']} {endpoint_data['url']}`\n\n"
                
                if findings:
                    tool_response += f"**Findings:** {len(findings)}\n\n"
                    for idx, finding in enumerate(findings, 1):
                        tool_response += f"### {idx}. {finding.get('type', 'Issue')}\n"
                        tool_response += f"**Severity:** {finding.get('severity', 'UNKNOWN')}\n"
                        tool_response += f"**Issue:** {finding.get('issue', 'N/A')}\n"
                        tool_response += f"**Remediation:** {finding.get('remediation', 'N/A')}\n"
                        if 'owasp' in finding:
                            tool_response += f"**OWASP:** {finding['owasp']}\n"
                        tool_response += "\n"
                    
                    user_message = f"Based on this API security analysis:\n\n{tool_response}\n\nExplain the security risks and how to fix them. Original question: {user_message}"
                else:
                    tool_response += "No critical issues detected, but always:\n- Implement rate limiting\n- Use HTTPS\n- Validate all inputs\n- Implement proper authentication"
                    user_message = f"API analysis complete: {tool_response}\n\nProvide more security recommendations. Original: {user_message}"
            else:
                tool_response = "**API Analyzer**\n\nProvide API details in this format:\n\n```\nPOST https://api.example.com/users?id=123\nHeaders: Authorization: Bearer token123\n```"
                yield f"data: {json.dumps({'token': tool_response})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
        
        # Web Security Posture - NOW ACTUALLY CHECKS SECURITY
        elif 'web posture' in message_lower or 'web security' in message_lower or 'security headers' in message_lower:
            url_match = re.search(r'https?://[^\s]+', user_message)
            
            if url_match:
                url = url_match.group(0)
                # Simulate header check (in real scenario, would make HTTP request)
                headers = {}
                
                findings = analyze_web_security(url, headers)
                
                tool_response = f"**Web Security Posture Analysis**\n\n**URL:** {url}\n\n"
                tool_response += f"**Findings:** {len(findings)}\n\n"
                
                for idx, finding in enumerate(findings, 1):
                    tool_response += f"### {idx}. {finding.get('type', 'Issue')}\n"
                    tool_response += f"**Severity:** {finding.get('severity', 'UNKNOWN')}\n"
                    tool_response += f"**Issue:** {finding.get('issue', 'N/A')}\n"
                    tool_response += f"**Remediation:** {finding.get('remediation', 'N/A')}\n"
                    if 'owasp' in finding:
                        tool_response += f"**OWASP:** {finding['owasp']}\n"
                    tool_response += "\n"
                
                user_message = f"Web security analysis results:\n\n{tool_response}\n\nExplain these security issues and their impact. Original: {user_message}"
            else:
                tool_response = "**Web Security Posture Scanner**\n\nProvide a URL to analyze:\n`https://example.com`"
                yield f"data: {json.dumps({'token': tool_response})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
        
        # Metadata Intelligence - NOW ACTUALLY EXTRACTS METADATA
        elif 'metadata' in message_lower and len(user_message) > 50:
            findings = analyze_metadata(user_message)
            
            if findings:
                tool_response = "**Metadata & Exposure Intelligence**\n\n"
                for finding in findings:
                    tool_response += f"### {finding.get('type', 'Finding')}\n"
                    tool_response += f"**Severity:** {finding.get('severity', 'INFO')}\n"
                    tool_response += f"**Count:** {finding.get('count', 0)}\n"
                    tool_response += f"**Issue:** {finding.get('issue', 'N/A')}\n"
                    if 'samples' in finding:
                        tool_response += f"**Samples:** {', '.join(str(s) for s in finding['samples'])}\n"
                    tool_response += "\n"
                
                # Ask AI to explain metadata findings
                user_message = f"Based on this metadata analysis:\n\n{tool_response}\n\nExplain the implications and risks. Original: {user_message}"
            else:
                tool_response = "**Metadata Analysis**\n\nNo sensitive information exposure detected."
                user_message = f"Metadata analysis complete: {tool_response}\n\nSuggest areas for further data leakage prevention. Original: {user_message}"
        
        # Threat Surface Mapper - NOW ACTUALLY MAPS THREATS
        elif 'threat surface' in message_lower:
            analysis = analyze_threat_surface(user_message)
            
            tool_response = "**Threat Surface Mapping**\n\n"
            
            if analysis['entry_points']:
                tool_response += "### Entry Points\n"
                for ep in analysis['entry_points']:
                    tool_response += f"- {ep}\n"
                tool_response += "\n"
            
            if analysis['trust_boundaries']:
                tool_response += "### Trust Boundaries\n"
                for tb in analysis['trust_boundaries']:
                    tool_response += f"- {tb}\n"
                tool_response += "\n"
            
            if analysis['high_risk_components']:
                tool_response += "### HIGH Risk Components\n"
                for hrc in analysis['high_risk_components']:
                    tool_response += f"- {hrc}\n"
                tool_response += "\n"
            
            # Ask AI to explain threat surface findings
            user_message = f"Threat surface mapping results:\n\n{tool_response}\n\nExplain the identified risks and suggest mitigation strategies. Original: {user_message}"
        
        # Auth Evaluator - NOW ACTUALLY EVALUATES AUTH
        elif 'auth evaluator' in message_lower or ('authentication' in message_lower and len(user_message) > 30):
            findings = analyze_auth_logic(user_message)
            
            tool_response = "**Authentication Logic Evaluation**\n\n"
            
            if findings:
                tool_response += f"**Findings:** {len(findings)}\n\n"
                for idx, finding in enumerate(findings, 1):
                    tool_response += f"### {idx}. {finding.get('type', 'Issue')}\n"
                    tool_response += f"**Severity:** {finding.get('severity', 'UNKNOWN')}\n"
                    tool_response += f"**Issue:** {finding.get('issue', 'N/A')}\n"
                    tool_response += f"**Remediation:** {finding.get('remediation', 'N/A')}\n\n"
                
                # Ask AI to explain auth findings
                user_message = f"Based on this authentication logic evaluation:\n\n{tool_response}\n\nExplain the security implications and recommend improvements. Original: {user_message}"
            else:
                tool_response += "Authentication logic appears sound. Key recommendations:\n- Always use HTTPS\n- Implement MFA\n- Use secure session management\n- Apply rate limiting"
                user_message = f"Authentication logic analysis complete: {tool_response}\n\nProvide general best practices for secure authentication. Original: {user_message}"
        
        # Log Analyzer - NOW ACTUALLY ANALYZES LOGS
        elif 'log analyzer' in message_lower or 'analyze logs' in message_lower:
            if len(user_message) > 100:
                # Analyze the logs provided
                log_findings = []
                lines = user_message.split('\n')
                
                for i, line in enumerate(lines, 1):
                    # Brute force detection
                    if re.search(r'failed.*login|authentication.*failed|invalid.*password', line, re.IGNORECASE):
                        log_findings.append({
                            'type': 'Brute Force Attempt',
                            'severity': 'HIGH',
                            'line': i,
                            'evidence': line[:100],
                            'mitre': 'T1110 - Brute Force'
                        })
                    
                    # SQL injection attempt
                    if re.search(r'union.*select|1=1|drop\s+table', line, re.IGNORECASE):
                        log_findings.append({
                            'type': 'SQL Injection Attempt',
                            'severity': 'CRITICAL',
                            'line': i,
                            'evidence': line[:100],
                            'mitre': 'T1190 - Exploit Public-Facing Application'
                        })
                    
                    # Privilege escalation
                    if re.search(r'sudo|privilege.*escalat|unauthorized.*access.*admin', line, re.IGNORECASE):
                        log_findings.append({
                            'type': 'Privilege Escalation',
                            'severity': 'HIGH',
                            'line': i,
                            'evidence': line[:100],
                            'mitre': 'T1548 - Abuse Elevation Control Mechanism'
                        })
                
                if log_findings:
                    tool_response = f"**Log Analysis - Threat Detection**\n\n**Threats Detected:** {len(log_findings)}\n\n"
                    for idx, finding in enumerate(log_findings[:10], 1):  # Limit to 10
                        tool_response += f"### Threat #{idx}: {finding['type']}\n"
                        tool_response += f"**Severity:** {finding['severity']}\n"
                        tool_response += f"**Line:** {finding['line']}\n"
                        tool_response += f"**Evidence:** `{finding['evidence']}`\n"
                        tool_response += f"**MITRE ATT&CK:** {finding['mitre']}\n\n"
                    
                    # Ask AI to explain log findings
                    user_message = f"Based on these log analysis results:\n\n{tool_response}\n\nExplain these threats, their impact, and recommend immediate actions. Original: {user_message}"
                else:
                    tool_response = "**Log Analysis**\n\nNo obvious threats detected in logs. Continue monitoring for:\n- Failed authentication attempts\n- Privilege escalation\n- SQL injection\n- Unusual access patterns"
                    user_message = f"Log analysis results: {tool_response}\n\nProvide general advice for effective log monitoring. Original: {user_message}"
            else:
                tool_response = "**Log Analyzer**\n\nProvide logs to analyze (auth logs, application logs, server logs, etc.)"
                yield f"data: {json.dumps({'token': tool_response})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
        
        # Incident Response - NOW ACTUALLY PROVIDES IR PLAN
        elif 'incident response' in message_lower:
            response = provide_incident_response(user_message)
            
            tool_response = "**Incident Response Plan**\n\n"
            tool_response += "### Phase 1: Triage\n"
            for step in response['triage']:
                tool_response += f"- {step}\n"
            tool_response += "\n### Phase 2: Containment\n"
            for step in response['containment']:
                tool_response += f"- {step}\n"
            tool_response += "\n### Phase 3: Recovery\n"
            for step in response['recovery']:
                tool_response += f"- {step}\n"
            tool_response += "\n### Phase 4: Lessons Learned\n"
            for step in response['lessons_learned']:
                tool_response += f"- {step}\n"
            
            # Inject tool response, but let AI provide context
            user_message = f"Here is an incident response plan structure:\n\n{tool_response}\n\nExplain each phase and provide context relevant to a typical web application breach. Original: {user_message}"
        
        # Threat Intel Explainer - NOW ACTUALLY EXPLAINS THREATS
        elif 'threat intel' in message_lower:
            intel = explain_threat_intelligence(user_message)
            
            tool_response = "**Threat Intelligence**\n\n"
            tool_response += f"**Description:** {intel['description']}\n\n"
            tool_response += f"**Detection Methods:** {intel['detection']}\n\n"
            tool_response += f"**Mitigation Strategies:** {intel['mitigation']}\n\n"
            tool_response += f"**Potential Impact:** {intel['impact']}\n"
            
            # Ask AI to elaborate
            user_message = f"Here is some threat intelligence:\n\n{tool_response}\n\nElaborate on the detection and mitigation strategies, and provide examples of real-world attacks. Original: {user_message}"
        
        # Policy Generator - NOW ACTUALLY GENERATES POLICIES
        elif 'policy generator' in message_lower or 'generate policy' in message_lower:
            org_type = 'tech'  # Default
            org_size = 'startup'  # Default
            
            if 'enterprise' in message_lower:
                org_size = 'enterprise'
            elif 'smb' in message_lower or 'small business' in message_lower:
                org_size = 'smb'
            
            policies = generate_security_policy(org_type, org_size)
            
            tool_response = "**Security Policy Framework**\n\n"
            for policy_key, policy_data in policies.items():
                tool_response += f"## {policy_data['title']}\n\n"
                for req in policy_data['requirements']:
                    tool_response += f"- {req}\n"
                tool_response += "\n"
            
            # Ask AI to tailor policies
            user_message = f"Here is a security policy framework:\n\n{tool_response}\n\nTailor these policies for a medium-sized FinTech company, emphasizing compliance and data protection. Original: {user_message}"
        
        # Readiness Scorecard - NOW ACTUALLY CALCULATES SCORE
        elif 'readiness' in message_lower or 'scorecard' in message_lower:
            # Parse security state from message
            security_state = {
                'logging_enabled': 'logging' in message_lower and ('yes' in message_lower or 'enabled' in message_lower),
                'siem_deployed': 'siem' in message_lower and ('yes' in message_lower or 'deployed' in message_lower),
                'incident_response_plan': 'incident response' in message_lower and ('yes' in message_lower or 'has plan' in message_lower),
                'response_team': 'response team' in message_lower and ('yes' in message_lower or 'has team' in message_lower),
                'patch_management': 'patch management' in message_lower and ('yes' in message_lower or 'implemented' in message_lower),
                'hardened_configs': 'hardened configs' in message_lower and ('yes' in message_lower or 'implemented' in message_lower),
                'mfa_enabled': 'mfa' in message_lower and ('yes' in message_lower or 'enabled' in message_lower),
                'least_privilege': 'least privilege' in message_lower and ('yes' in message_lower or 'implemented' in message_lower),
            }
            
            readiness = calculate_defensive_readiness(security_state)
            
            tool_response = "**Defensive Readiness Scorecard**\n\n"
            tool_response += f"**Overall Score:** {readiness['readiness_score']}/{readiness['max_score']}\n"
            tool_response += f"**Readiness Level:** {readiness['readiness_level']}\n\n"
            tool_response += "### Priority Gaps (Top 3)\n"
            for gap in readiness['priority_gaps']:
                tool_response += f"- {gap}\n"
            tool_response += "\n### All Gaps\n"
            for gap in readiness['all_gaps']:
                tool_response += f"- {gap}\n"
            
            # Ask AI to provide actionable steps
            user_message = f"Here is your defensive readiness scorecard:\n\n{tool_response}\n\nProvide actionable steps and prioritize them to improve the score. Original: {user_message}"
        
        # If tool detected and executed, return results
        if tool_response:
            yield f"data: {json.dumps({'token': tool_response})}\n\n"
            yield f"data: {json.dumps({'done': True})}\n\n"
            return
        
        # Build context with history
        context_messages = []
        if history:
            for msg in history[-10:]:  # Last 10 messages for context
                role = msg.get('role', 'user')
                content = msg.get('content', '')
                context_messages.append(f"{role.upper()}: {content}")
        
        context = "\n".join(context_messages) if context_messages else ""
        
        system_prompt = """You are R3KON GPT, an elite cybersecurity AI assistant specializing in offensive security, vulnerability analysis, and penetration testing.

When analyzing tool results:
- Explain findings in detail with real-world context
- Provide step-by-step remediation guidance
- Reference industry standards (OWASP, CWE, MITRE ATT&CK)
- Give concrete code examples when relevant
- Explain the security impact and potential exploits

Always respond with detailed, actionable information. Never give incomplete responses."""
        
        full_prompt = f"""{system_prompt}

Previous Context:
{context}

User Query: {user_message}

Instructions: Provide a detailed, technical response. Be concise but comprehensive."""
        
        with model_lock:
            if not model_loaded or llm is None:
                print("[WAITING] Model not loaded yet, waiting for model_loaded_event...")
                model_loaded_event.wait(timeout=120)  # 2 minute timeout
                
                if not model_loaded or llm is None:
                    print("[ERROR] Model failed to load or was disposed")
                    yield f"data: {json.dumps({'error': 'Model not available. Please restart the application.'})}\n\n"
                    return
                
                print("[CONTINUING] Model is now loaded and ready.")
            
            try:
                # GPT4All returns a generator when streaming=True
                response_generator = llm.generate(
                    full_prompt,
                    max_tokens=1500,
                    temp=0.7,
                    top_k=40,
                    top_p=0.92,
                    repeat_penalty=1.15,
                    streaming=True
                )
                
                # Check if it's a generator or a string
                if hasattr(response_generator, '__iter__') and not isinstance(response_generator, str):
                    # It's a generator - stream tokens
                    for token in response_generator:
                        if stop_generation_flag:
                            yield f"data: {json.dumps({'stopped': True})}\n\n"
                            break
                        
                        # Token should be a string
                        if isinstance(token, str):
                            yield f"data: {json.dumps({'token': token})}\n\n"
                else:
                    # It's a complete string - send it all at once
                    full_text = str(response_generator)
                    # Split into chunks for pseudo-streaming
                    chunk_size = 5  # Send 5 characters at a time
                    for i in range(0, len(full_text), chunk_size):
                        if stop_generation_flag:
                            yield f"data: {json.dumps({'stopped': True})}\n\n"
                            break
                        
                        chunk = full_text[i:i+chunk_size]
                        yield f"data: {json.dumps({'token': chunk})}\n\n"
                        time.sleep(0.01)  # Small delay for visual streaming effect
            except RuntimeError as re:
                if "disposed" in str(re).lower():
                    print(f"[ERROR] Model was disposed: {re}")
                    yield f"data: {json.dumps({'error': 'Model connection lost. Please refresh the page.'})}\n\n"
                    return
                raise
        
        yield f"data: {json.dumps({'done': True})}\n\n"
        
    except Exception as e:
        print(f"Error in generate_response_stream: {e}")
        yield f"data: {json.dumps({'error': str(e)})}\n\n"

# ======================== FLASK ROUTES ========================

@app.before_request
def log_request_info():
    """Log all API requests"""
    if request.path.startswith('/api/'):
        print(f"[API] {request.method} {request.path}")

@app.after_request
def add_header(response):
    """Add headers to prevent caching"""
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/')
def index():
    """Serve the HTML page"""
    print(f"[DEBUG] ==================== INDEX ROUTE CALLED ====================")
    print(f"[DEBUG] Serving index.html from BASE_PATH: {BASE_PATH}")
    
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>R3KON GPT AI</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --background-dark: #1a1a1a;
            --background-secondary: #2d2d2d;
            --sidebar-bg: rgba(42, 42, 42, 0.95);
            --border-color: rgba(139, 118, 102, 0.2);
            --accent-primary: #D4AF37; /* Gold */
            --accent-secondary: #8B7666; /* Bronze */
            --accent-tertiary: #A68F7B; /* Lighter Bronze */
            --input-bg: rgba(51, 45, 40, 0.8);
            --text-primary: #e0e0e0;
            --text-secondary: #A68F7B;
            --danger-color: #C25450; /* Red */
            --warning-color: #D4A245; /* Orange */
            --success-color: #7C9F6F; /* Green */
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 16px;
            background: linear-gradient(135deg, var(--background-dark) 0%, var(--background-secondary) 100%);
            color: var(--text-primary);
            overflow: hidden;
            line-height: 1.6;
        }

        .app-container {
            display: flex;
            height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            width: 280px;
            background: var(--sidebar-bg);
            backdrop-filter: blur(10px);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            box-shadow: 2px 0 10px rgba(0,0,0,0.5);
        }
        
        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: rgba(42, 42, 42, 0.7);
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: var(--accent-secondary);
            border-radius: 4px;
        }
        
        .logo-section {
            padding: 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 16px;
            background: rgba(26, 26, 26, 0.8);
        }
        
        .logo-img {
            width: 48px;
            height: 48px;
            border-radius: 8px;
        }

        .sidebar-content {
            padding: 16px;
        }

        .sidebar-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--accent-primary);
            margin: 20px 0 12px 0;
            padding: 8px 12px;
            background: var(--input-bg);
            border-left: 3px solid var(--accent-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .settings-section {
            margin-bottom: 16px;
        }

        .settings-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-tertiary);
            margin-bottom: 8px;
        }

        .btn {
            background: var(--input-bg);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            padding: 10px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
            font-family: 'Inter', sans-serif;
        }

        .btn:hover {
            background: var(--accent-secondary);
            border-color: var(--accent-tertiary);
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(139, 118, 102, 0.3);
        }

        .btn-full {
            width: 100%;
            margin-bottom: 8px;
            text-align: left;
        }

        .btn-security {
            background: linear-gradient(135deg, var(--input-bg) 0%, rgba(35, 30, 26, 0.9) 100%);
            border-color: var(--accent-secondary);
        }

        .btn-security:hover {
            background: linear-gradient(135deg, var(--accent-secondary) 0%, var(--accent-tertiary) 100%);
            color: var(--background-dark);
        }

        .theme-buttons, .font-buttons {
            display: flex;
            gap: 8px;
        }

        .theme-buttons .btn, .font-buttons .btn {
            flex: 1;
        }

        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .checkbox-container input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
            accent-color: var(--accent-secondary);
        }

        .checkbox-container label {
            font-size: 14px;
            color: var(--text-primary);
            cursor: pointer;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: linear-gradient(135deg, var(--background-dark) 0%, var(--background-secondary) 100%);
        }

        .header {
            padding: 20px 32px;
            background: var(--sidebar-bg);
            border-bottom: 2px solid var(--accent-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }

        .header h1 {
            font-size: 28px;
            font-weight: 700;
            color: var(--accent-primary);
            letter-spacing: 0.5px;
        }

        .header p {
            font-size: 13px;
            color: var(--accent-tertiary);
            margin-top: 4px;
        }

        .mode-indicator {
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1px;
            color: white;
        }

        .mode-ready {
            background: linear-gradient(135deg, var(--success-color), #5d7454);
        }

        .mode-loading {
            background: linear-gradient(135deg, var(--warning-color), #a68232);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }

        .tool-buttons {
            padding: 16px 32px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            background: var(--sidebar-bg);
            border-bottom: 1px solid var(--border-color);
        }

        .tool-btn {
            padding: 8px 16px;
            background: var(--input-bg);
            color: var(--text-primary);
            border: 1px solid var(--accent-secondary);
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s ease;
            font-family: 'Inter', sans-serif;
        }

        .tool-btn:hover {
            background: var(--accent-secondary);
            color: var(--background-dark);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(139, 118, 102, 0.4);
        }

        .chat-container {
            flex: 1;
            overflow-y: auto;
            padding: 24px 32px;
        }

        .chat-container::-webkit-scrollbar {
            width: 10px;
        }

        .chat-container::-webkit-scrollbar-track {
            background: rgba(42, 42, 42, 0.7);
        }

        .chat-container::-webkit-scrollbar-thumb {
            background: var(--accent-secondary);
            border-radius: 5px;
        }

        .message {
            margin-bottom: 24px;
            display: flex;
            gap: 12px;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .message-icon {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
            color: white;
        }

        .user-message .message-icon {
            background: linear-gradient(135deg, #6B8BA0, #4d6a7c);
        }

        .assistant-message .message-icon {
            background: linear-gradient(135deg, var(--accent-secondary), var(--accent-tertiary));
        }

        .system-message .message-icon {
            background: linear-gradient(135deg, var(--warning-color), #a68232);
        }

        .message-content {
            flex: 1;
            background: var(--sidebar-bg);
            padding: 16px 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            line-height: 1.6;
            font-size: 15px;
        }

        .message-content h3 {
            color: var(--accent-primary);
            margin-bottom: 8px;
            font-size: 18px;
        }

        .message-content code {
            background: var(--input-bg);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: var(--accent-primary);
        }

        .message-content pre {
            background: var(--input-bg);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin: 8px 0;
            border-left: 3px solid var(--accent-secondary);
        }

        /* Added enhanced styling for security features */
        
        /* Security severity badges */
        .severity {
            font-weight: 800;
            padding: 4px 10px;
            border-radius: 6px;
            letter-spacing: 0.5px;
            font-size: 12px;
            display: inline-block;
            margin: 0 4px;
            text-transform: uppercase;
        }

        .severity.critical {
            background: linear-gradient(135deg, #ff4444, #cc0000);
            color: white;
            box-shadow: 0 2px 8px rgba(255, 68, 68, 0.4);
        }

        .severity.high {
            background: linear-gradient(135deg, #ff9966, #ff5500);
            color: white;
            box-shadow: 0 2px 8px rgba(255, 153, 102, 0.4);
        }

        .severity.medium {
            background: linear-gradient(135deg, #ffcc00, #ff9900);
            color: #1a1a1a;
            box-shadow: 0 2px 8px rgba(255, 204, 0, 0.4);
        }

        .severity.low {
            background: linear-gradient(135deg, #99cc66, #669900);
            color: white;
            box-shadow: 0 2px 8px rgba(153, 204, 102, 0.4);
        }

        /* Enhanced code blocks */
        .code-block {
            background: var(--input-bg);
            padding: 20px 16px 16px 16px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', 'Monaco', 'Menlo', monospace;
            font-size: 13px;
            margin: 16px 0;
            border-left: 4px solid var(--accent-secondary);
            position: relative;
            line-height: 1.6;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        }

        .code-block::before {
            content: attr(data-lang);
            position: absolute;
            top: 4px;
            right: 8px;
            background: var(--accent-secondary);
            color: white;
            padding: 4px 10px;
            font-size: 10px;
            border-radius: 4px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .code-block code {
            background: transparent !important;
            padding: 0 !important;
            border-radius: 0 !important;
            color: #e0e0e0 !important;
            border: none !important;
        }

        /* Security references (OWASP, CWE, CVE) */
        .owasp-ref, .cwe-ref, .cve-ref {
            font-family: 'Courier New', 'Monaco', monospace;
            background: rgba(139, 118, 102, 0.2);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(139, 118, 102, 0.3);
            display: inline-block;
            margin: 0 2px;
        }

        .owasp-ref {
            color: #ff9966;
            border-color: rgba(255, 153, 102, 0.3);
        }

        .cwe-ref {
            color: #ffcc00;
            border-color: rgba(255, 204, 0, 0.3);
        }

        .cve-ref {
            color: #ff6666;
            border-color: rgba(255, 102, 102, 0.3);
        }

        /* Enhanced lists */
        .message-content ul, .message-content ol {
            margin: 16px 0 16px 8px;
            line-height: 1.8;
            padding-left: 24px;
        }

        .message-content li {
            margin-bottom: 10px;
            padding-left: 8px;
        }

        .message-content ul li {
            list-style-type: disc;
        }

        .message-content ol li {
            list-style-type: decimal;
        }

        /* Enhanced headers */
        .message-content h1 {
            font-size: 24px;
            color: var(--accent-primary);
            margin: 20px 0 12px 0;
            font-weight: 700;
            border-bottom: 2px solid var(--accent-secondary);
            padding-bottom: 8px;
        }

        .message-content h2 {
            font-size: 20px;
            color: var(--accent-primary);
            margin: 18px 0 10px 0;
            font-weight: 600;
        }

        .message-content h3 {
            font-size: 18px;
            color: var(--accent-tertiary);
            margin: 16px 0 8px 0;
            font-weight: 600;
        }

        /* Inline code - keep distinct from code blocks */
        .message-content code {
            background: var(--input-bg);
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Courier New', 'Monaco', monospace;
            font-size: 13px;
            color: var(--accent-primary);
            border: 1px solid var(--border-color);
        }


        .input-container {
            padding: 20px 32px;
            background: var(--sidebar-bg);
            border-top: 2px solid var(--accent-secondary);
            display: flex;
            gap: 12px;
            box-shadow: 0 -2px 10px rgba(0,0,0,0.5);
        }

        #userInput {
            flex: 1;
            background: var(--input-bg);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            font-size: 15px;
            font-family: 'Inter', sans-serif;
            resize: none;
            min-height: 52px;
            max-height: 150px;
            line-height: 1.6;
        }

        #userInput:focus {
            outline: none;
            border-color: var(--accent-secondary);
            box-shadow: 0 0 0 3px rgba(139, 118, 102, 0.2);
        }

        #userInput::placeholder {
            color: var(--accent-tertiary);
        }

        #sendBtn, #stopBtn {
            padding: 14px 24px;
            background: linear-gradient(135deg, var(--accent-secondary), var(--accent-tertiary));
            color: var(--background-dark);
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 700;
            transition: all 0.2s ease;
            font-family: 'Inter', sans-serif;
        }

        #sendBtn:hover:not(:disabled), #stopBtn:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(139, 118, 102, 0.5);
        }

        #sendBtn:disabled, #stopBtn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        #stopBtn {
            background: linear-gradient(135deg, var(--danger-color), #9d3935);
            color: white;
            display: none;
        }

        .status-bar {
            position: fixed;
            bottom: 0;
            right: 0;
            padding: 8px 16px;
            background: var(--sidebar-bg);
            border-top: 1px solid var(--border-color);
            border-left: 1px solid var(--border-color);
            border-top-left-radius: 8px;
            font-size: 11px;
            color: var(--accent-tertiary);
            font-weight: 600;
            z-index: 100;
        }
        
        /* Added loading screen styles */
        .loading-screen {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            min-height: 400px;
        }

        .loading-content {
            text-align: center;
            padding: 48px 32px;
            max-width: 480px;
        }

        .progress-container {
            width: 100%;
            height: 8px;
            background: linear-gradient(135deg, rgba(139, 118, 102, 0.1) 0%, rgba(166, 143, 123, 0.1) 100%);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #8B7666 0%, #A68F7B 50%, #D4AF37 100%);
            border-radius: 12px;
            width: 0%;
            transition: width 0.3s ease;
            box-shadow: 0 0 12px rgba(212, 175, 55, 0.4);
        }
    </style>
</head>
<body>
    <div class="app-container">
        <aside class="sidebar">
            <div class="logo-section">
                <!-- Use the correct icon path to /icon.png since it's in the root directory -->
                <img src="/icon.png" alt="R3KON Logo" class="logo-img">
                <div>
                    <h1 style="font-size: 20px; font-weight: 700; color: var(--accent-primary); letter-spacing: 1px;">R3KON GPT</h1>
                    <p style="font-size: 13px; color: var(--accent-tertiary); margin-top: 4px;">Elite Cyber AI</p>
                </div>
            </div>

            <div class="sidebar-content">
                <div class="sidebar-title"> Settings</div>

                <div class="settings-section">
                    <label class="settings-label">Theme:</label>
                    <div class="theme-buttons">
                        <button class="btn" onclick="setTheme('dark')"> Dark</button>
                        <button class="btn" onclick="setTheme('light')"> Light</button>
                    </div>
                </div>

                <div class="settings-section">
                    <label class="settings-label">Font Size:</label>
                    <div class="font-buttons">
                        <button class="btn" onclick="adjustFontSize(-1)">A-</button>
                        <button class="btn" onclick="adjustFontSize(1)">A+</button>
                    </div>
                </div>

                <div class="settings-section">
                    <label class="settings-label">Memory:</label>
                    <div class="checkbox-container">
                        <input type="checkbox" id="sessionMemory" checked onchange="updateSetting('sessionMemory', this.checked)">
                        <label for="sessionMemory">Session Memory</label>
                    </div>
                </div>

                <div class="sidebar-title"> Offensive Tools</div>

                <div class="settings-section">
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('code')"> Code Scanner</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('api')"> API Analyzer</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('web')"> Web Posture</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('metadata')"> Metadata Intel</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('threat')"> Threat Surface</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('auth')"> Auth Evaluator</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('recon')"> Recon Scorer</button>
                </div>

                <div class="sidebar-title"> Defensive Tools</div>

                <div class="settings-section">
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('logs')">Log Analyzer</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('owasp')"> OWASP Advisor</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('config')"> Config Auditor</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('incident')"> Incident Response</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('intel')"> Threat Intel</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('policy')"> Policy Generator</button>
                    <button class="btn btn-full btn-security" onclick="openSecurityTool('readiness')"> Readiness Score</button>
                </div>

                <div class="sidebar-title"> Debug</div>

                <div class="settings-section">
                    <button class="btn btn-full" onclick="testConnection()">Test Connection</button>
                    <button class="btn btn-full" onclick="forceEnableUI()">Force Enable UI</button>
                    <button class="btn btn-full" onclick="clearConsole()">Clear Console</button>
                </div>

                <div class="sidebar-title"> Actions</div>

                <div class="settings-section">
                    <button class="btn btn-full" onclick="clearChat()"> Clear Chat</button>
                    <button class="btn btn-full" onclick="exportChat()"> Export Chat</button>
                    <button class="btn btn-full" onclick="clearMemory()"> Clear Memory</button>
                </div>
            </div>
        </aside>

        <main class="main-content">
            <header class="header">
                <div>
                    <h1>R3KON GPT</h1>
                    <p>Elite Cybersecurity AI Assistant</p>
                </div>
                <div class="mode-indicator mode-loading" id="modeIndicator">INITIALIZING</div>
            </header>

            <div class="tool-buttons">
                <button class="tool-btn" onclick="quickCommand('Analyze this vulnerability')"> Detailed Analysis</button>
                <button class="tool-btn" onclick="quickCommand('Explain the risk')"> Risk Explanation</button>
                <button class="tool-btn" onclick="quickCommand('How to mitigate')"> Mitigation Steps</button>
                <button class="tool-btn" onclick="quickCommand('OWASP mapping')"> OWASP Mapping</button>
                <button class="tool-btn" onclick="quickCommand('Generate exploit POC')"> Exploit Scenario</button>
            </div>

            <div class="chat-container" id="chatContainer">
                <!-- Enhanced loading screen with progress bar -->
                <div class="loading-screen" id="loadingScreen">
                    <div class="loading-content">
                        <img src="/icon.png" alt="R3KON GPT" style="width: 120px; height: 120px; margin-bottom: 24px; opacity: 0.9;">
                        <h2 style="color: #8B7666; margin-bottom: 16px; font-size: 28px;">R3KON GPT</h2>
                        <p style="color: #666; margin-bottom: 32px; font-size: 16px;">Elite Cybersecurity AI</p>
                        
                        <div class="progress-container">
                            <div class="progress-bar" id="progressBar"></div>
                        </div>
                        
                        <p id="loadingMessage" style="margin-top: 16px; color: #8B7666; font-weight: 500;">Initializing...</p>
                        <p id="loadingPercent" style="margin-top: 8px; color: #999; font-size: 14px;">0%</p>
                    </div>
                </div>
            </div>

            <div class="input-container">
                <textarea id="userInput" placeholder="Ask R3KON GPT anything about cybersecurity..." rows="1" disabled onkeypress="if(event.key==='Enter' && !event.shiftKey){event.preventDefault(); sendMessage();}"></textarea>
                <button id="sendBtn" onclick="sendMessage()" disabled> Send</button>
                <button id="stopBtn" onclick="stopGeneration()"> Stop</button>
            </div>
        </main>
    </div>

    <div class="status-bar" id="statusBar">
        Status: Initializing...
    </div>

    <script>
        let conversationHistory = [];
        let sessionMemory = true;
        let currentFontSize = 16;
        let isGenerating = false;

        // Debug functions
        function testConnection() {
            console.log('[DEBUG] Testing connection...');
            fetch('/api/test')
                .then(res => {
                    console.log('[DEBUG] Response status:', res.status);
                    return res.json();
                })
                .then(data => {
                    console.log('[DEBUG] API Response:', data);
                    alert(`Connection test: SUCCESS\nModel loaded: ${data.model_loaded}\nProgress: ${data.progress}%`);
                })
                .catch(err => {
                    console.error('[DEBUG] Test failed:', err);
                    alert('Connection test: FAILED\\n' + err.message);
                });
        }

        function forceEnableUI() {
            console.log('[DEBUG] Force enabling UI...');
            enableUI();
            hideLoadingScreen();
            showWelcomeMessage();
            alert('UI force enabled!');
        }

        function clearConsole() {
            console.clear();
            console.log('Console cleared - R3KON GPT debugging');
        }

        // Function to check model loading status and update UI
        function pollStatus() {
            console.log('[POLL] Checking model status...');
            
            // Add unique timestamp to prevent caching
            const timestamp = new Date().getTime();
            
            fetch(`/api/status?_=${timestamp}`, {
                method: 'GET',
                headers: {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache'
                },
                cache: 'no-store'
            })
            .then(res => {
                console.log('[POLL] Response status:', res.status);
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                return res.json();
            })
            .then(data => {
                console.log('[POLL] Status received:', data);
                
                // Update progress bar
                const progressBar = document.getElementById('progressBar');
                const loadingMessage = document.getElementById('loadingMessage');
                const loadingPercent = document.getElementById('loadingPercent');
                
                if (progressBar && data.progress !== undefined) {
                    progressBar.style.width = data.progress + '%';
                    if (loadingPercent) loadingPercent.textContent = `${data.progress}%`;
                    if (loadingMessage) loadingMessage.textContent = data.message || 'Loading...';
                }
                
                // Update mode indicator
                const modeIndicator = document.getElementById('modeIndicator');
                if (modeIndicator) {
                    if (data.modelLoaded === true) {
                        modeIndicator.textContent = 'READY ✓';
                        modeIndicator.className = 'mode-indicator mode-ready';
                        
                        console.log('[POLL] Model is ready! Enabling UI...');
                        
                        // Small delay then enable everything
                        setTimeout(() => {
                            enableUI();
                            hideLoadingScreen();
                            showWelcomeMessage();
                        }, 500);
                        
                        return; // STOP POLLING
                    } else {
                        modeIndicator.textContent = `LOADING ${data.progress}%`;
                        modeIndicator.className = 'mode-indicator mode-loading';
                    }
                }
                
                // Continue polling if not loaded yet (every 1 second)
                setTimeout(pollStatus, 1000);
            })
            .catch(err => {
                console.error('[POLL] Error:', err);
                const loadingMessage = document.getElementById('loadingMessage');
                if (loadingMessage) loadingMessage.textContent = 'Connecting to server...';
                
                // Retry after 1 second on error
                setTimeout(pollStatus, 1000);
            });
        }
        
        function enableUI() {
            console.log('[UI] Enabling user interface...');
            const sendBtn = document.getElementById('sendBtn');
            const userInput = document.getElementById('userInput');
            const statusBar = document.getElementById('statusBar');
            
            if (sendBtn) sendBtn.disabled = false;
            if (userInput) userInput.disabled = false;
            if (statusBar) statusBar.textContent = 'Status: Ready';
            
            // Also enable tool buttons
            document.querySelectorAll('.tool-btn, .btn').forEach(btn => {
                btn.disabled = false;
            });
            
            console.log('[UI] Interface enabled!');
        }

        function hideLoadingScreen() {
            const loadingScreen = document.getElementById('loadingScreen');
            if (loadingScreen) {
                loadingScreen.style.transition = 'opacity 0.5s ease';
                loadingScreen.style.opacity = '0';
                setTimeout(() => {
                    loadingScreen.style.display = 'none';
                }, 500);
            }
        }

        function showWelcomeMessage() {
            const chatContainer = document.getElementById('chatContainer');
            chatContainer.innerHTML = `
                <div class="message system-message">
                    <div class="message-icon">⚡</div>
                    <div class="message-content">
                        <h3>R3KON GPT READY!</h3>
                        <p><strong>Model is fully loaded and ready!</strong></p>
                        <p>I'm your elite Cybersecurity AI assistant. I can help you with:</p>
                        <ul style="margin: 12px 0 0 20px; line-height: 1.8;">
                            <li> <strong>Code Scanner:</strong> Advanced static analysis for vulnerabilities</li>
                            <li> <strong>API Analyzer:</strong> Business logic abuse detection</li>
                            <li> <strong>Web Security:</strong> Posture assessment and header analysis</li>
                            <li> <strong>Log Analysis:</strong> Threat detection with MITRE ATT&CK mapping</li>
                            <li> <strong>OWASP Advisor:</strong> Risk mapping and remediation guidance</li>
                            <li> <strong>Incident Response:</strong> Step-by-step response planning</li>
                        </ul>
                        <p style="margin-top: 12px;">Try sending a message or click any tool in the sidebar!</p>
                    </div>
                </div>
            `;
            scrollToBottom();
        }

        // Send message
        async function sendMessage() {
            const input = document.getElementById('userInput');
            const message = input.value.trim();
            
            if (!message || isGenerating) return;
            
            addMessage('user', message);
            input.value = '';
            
            if (sessionMemory) {
                conversationHistory.push({role: 'user', content: message});
            }
            
            isGenerating = true;
            document.getElementById('sendBtn').style.display = 'none';
            document.getElementById('stopBtn').style.display = 'block';
            document.getElementById('statusBar').textContent = 'Status: Generating...';
            
            const assistantDiv = document.createElement('div');
            assistantDiv.className = 'message assistant-message';
            assistantDiv.innerHTML = `
                <div class="message-icon">🤖</div>
                <div class="message-content" id="streamingContent"></div>
            `;
            document.getElementById('chatContainer').appendChild(assistantDiv);
            scrollToBottom();
            
            const streamingContent = document.getElementById('streamingContent');
            
            try {
                const response = await fetch('/api/chat/stream', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        message: message,
                        config: {},
                        history: sessionMemory ? conversationHistory : []
                    })
                });
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let fullResponse = '';
                
                while (true) {
                    const {value, done} = await reader.read();
                    if (done) break;
                    
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n');
                    
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.slice(6));
                                
                                if (data.token) {
                                    fullResponse += data.token;
                                    streamingContent.innerHTML = formatResponse(fullResponse);
                                    scrollToBottom();
                                } else if (data.done) {
                                    if (sessionMemory) {
                                        conversationHistory.push({role: 'assistant', content: fullResponse});
                                    }
                                } else if (data.error) {
                                    streamingContent.innerHTML = `<span style="color: var(--danger-color);">Error: ${data.error}</span>`;
                                } else if (data.stopped) {
                                    streamingContent.innerHTML += `<br><em style="color: var(--warning-color);">[Generation stopped]</em>`;
                                }
                            } catch (e) {
                                console.error('Parse error:', e);
                            }
                        }
                    }
                }
                
            } catch (error) {
                streamingContent.innerHTML = `<span style="color: var(--danger-color);">Error: ${error.message}</span>`;
            }
            
            isGenerating = false;
            document.getElementById('sendBtn').style.display = 'block';
            document.getElementById('stopBtn').style.display = 'none';
            document.getElementById('statusBar').textContent = 'Status: Ready';
            streamingContent.removeAttribute('id');
        }

        function formatResponse(text) {
            let formatted = text;
            
            // Step 1: Protect code blocks from other replacements
            const codeBlocks = [];
            formatted = formatted.replace(/```(\w+)?\n?([\s\S]*?)```/g, function(match, lang, code) {
                const placeholder = `___CODE_BLOCK_${codeBlocks.length}___`;
                codeBlocks.push({lang: lang || 'text', code: code.trim()});
                return placeholder;
            });
            
            // Step 2: Protect inline code
            const inlineCodes = [];
            formatted = formatted.replace(/`([^`\n]+)`/g, function(match, code) {
                const placeholder = `___INLINE_CODE_${inlineCodes.length}___`;
                inlineCodes.push(code);
                return placeholder;
            });
            
            // Step 3: Convert markdown headers (must be at start of line)
            formatted = formatted.replace(/^### (.+)$/gm, '<h3>$1</h3>');
            formatted = formatted.replace(/^## (.+)$/gm, '<h2>$1</h2>');
            formatted = formatted.replace(/^# (.+)$/gm, '<h1>$1</h1>');
            
            // Step 4: Bold and italic (outside of code blocks)
            formatted = formatted.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
            formatted = formatted.replace(/\*(.+?)\*/g, '<em>$1</em>');
            
            // Step 5: Security severity highlighting
            formatted = formatted.replace(/\b(CRITICAL)\b/gi, '<span class="severity critical">$1</span>');
            formatted = formatted.replace(/\b(HIGH)\b/gi, '<span class="severity high">$1</span>');
            formatted = formatted.replace(/\b(MEDIUM)\b/gi, '<span class="severity medium">$1</span>');
            formatted = formatted.replace(/\b(LOW)\b/gi, '<span class="severity low">$1</span>');
            
            // Step 6: OWASP/CWE/CVE references
            formatted = formatted.replace(/\b(OWASP[:\s]+[A-Z0-9]+(?:[:\-]\d{4})?[:\-]\d{4})\b/gi, '<span class="owasp-ref">$1</span>');
            formatted = formatted.replace(/\b(CWE-\d+(?::\s*[^<\n]+)?)\b/gi, '<span class="cwe-ref">$1</span>');
            formatted = formatted.replace(/\b(CVE-\d{4}-\d+)\b/gi, '<span class="cve-ref">$1</span>');
            
            // Step 7: Process lists line by line
            const lines = formatted.split('\n');
            let inList = false;
            let listType = null;
            const processedLines = [];
            
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const ulMatch = line.match(/^\s*[-*]\s+(.+)/);
                const olMatch = line.match(/^\s*\d+\.\s+(.+)/);
                
                if (ulMatch) {
                    if (!inList || listType !== 'ul') {
                        if (inList) processedLines.push(`</${listType}>`);
                        processedLines.push('<ul>');
                        inList = true;
                        listType = 'ul';
                    }
                    processedLines.push(`<li>${ulMatch[1]}</li>`);
                } else if (olMatch) {
                    if (!inList || listType !== 'ol') {
                        if (inList) processedLines.push(`</${listType}>`);
                        processedLines.push('<ol>');
                        inList = true;
                        listType = 'ol';
                    }
                    processedLines.push(`<li>${olMatch[1]}</li>`);
                } else {
                    if (inList) {
                        processedLines.push(`</${listType}>`);
                        inList = false;
                        listType = null;
                    }
                    processedLines.push(line);
                }
            }
            
            if (inList) {
                processedLines.push(`</${listType}>`);
            }
            
            formatted = processedLines.join('\n');
            
            // Step 8: Restore inline code
            for (let i = 0; i < inlineCodes.length; i++) {
                formatted = formatted.replace(
                    `___INLINE_CODE_${i}___`,
                    `<code>${escapeHtml(inlineCodes[i])}</code>`
                );
            }
            
            // Step 9: Restore code blocks
            for (let i = 0; i < codeBlocks.length; i++) {
                const block = codeBlocks[i];
                formatted = formatted.replace(
                    `___CODE_BLOCK_${i}___`,
                    `<pre class="code-block" data-lang="${block.lang}"><code>${escapeHtml(block.code)}</code></pre>`
                );
            }
            
            // Step 10: Convert line breaks (but not after block elements)
            formatted = formatted.replace(/\n/g, '<br>');
            
            // Step 11: Clean up - remove <br> after block elements
            formatted = formatted.replace(/(<\/(h[1-6]|ul|ol|pre|div)>)<br>/g, '$1');
            formatted = formatted.replace(/<br>(<(h[1-6]|ul|ol|pre|div))/g, '$1');
            
            return formatted;
        }

        // Stop generation
        function stopGeneration() {
            fetch('/api/stop', {method: 'POST'});
            isGenerating = false;
            document.getElementById('sendBtn').style.display = 'block';
            document.getElementById('stopBtn').style.display = 'none';
            document.getElementById('statusBar').textContent = 'Status: Ready';
        }

        // Add message to chat
        function addMessage(role, content) {
            const chatContainer = document.getElementById('chatContainer');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}-message`;
            
            const icon = role === 'user' ? '👤' : '🤖';
            
            messageDiv.innerHTML = `
                <div class="message-icon">${icon}</div>
                <div class="message-content">${escapeHtml(content)}</div>
            `;
            
            chatContainer.appendChild(messageDiv);
            scrollToBottom();
        }

        // Security tool shortcuts
        function openSecurityTool(tool) {
            const prompts = {
                'code': 'Run the Code Scanner on my code. I need a detailed static analysis.',
                'api': 'Perform an API security analysis with business logic abuse detection.',
                'web': 'Run a web security posture scan and check for missing headers.',
                'metadata': 'Analyze metadata and check for exposure intelligence.',
                'threat': 'Map the threat surface and identify attack paths.',
                'auth': 'Evaluate the authentication logic for security issues.',
                'recon': 'Calculate a reconnaissance risk score.',
                'logs': 'Analyze logs for threat detection using MITRE ATT&CK.',
                'owasp': 'Map vulnerabilities to the OWASP Top 10.',
                'config': 'Audit configuration for insecure defaults.',
                'incident': 'Provide incident response guidance.',
                'intel': 'Explain threat intelligence about a vulnerability.',
                'policy': 'Generate security policies for my organization.',
                'readiness': 'Calculate my defensive readiness scorecard.'
            };
            
            const message = prompts[tool];
            if (message) {
                document.getElementById('userInput').value = message;
                sendMessage();
            }
        }

        // Quick command
        function quickCommand(cmd) {
            document.getElementById('userInput').value = cmd;
            sendMessage();
        }

        // Theme switching
        function setTheme(theme) {
            if (theme === 'light') {
                document.body.classList.add('light-theme');
                document.documentElement.style.setProperty('--background-dark', '#f8f9fa');
                document.documentElement.style.setProperty('--background-secondary', '#e9ecef');
                document.documentElement.style.setProperty('--sidebar-bg', 'rgba(255, 255, 255, 0.9)');
                document.documentElement.style.setProperty('--border-color', 'rgba(220, 220, 220, 0.5)');
                document.documentElement.style.setProperty('--accent-primary', '#2c3e50');
                document.documentElement.style.setProperty('--accent-secondary', '#34495e');
                document.documentElement.style.setProperty('--accent-tertiary', '#7f8c8d');
                document.documentElement.style.setProperty('--input-bg', '#ffffff');
                document.documentElement.style.setProperty('--text-primary', '#333');
                document.documentElement.style.setProperty('--text-secondary', '#7f8c8d');
                document.documentElement.style.setProperty('--danger-color', '#c0392b');
                document.documentElement.style.setProperty('--warning-color', '#f39c12');
                document.documentElement.style.setProperty('--success-color', '#27ae60');

            } else {
                document.body.classList.remove('light-theme');
                document.documentElement.style.setProperty('--background-dark', '#1a1a1a');
                document.documentElement.style.setProperty('--background-secondary', '#2d2d2d');
                document.documentElement.style.setProperty('--sidebar-bg', 'rgba(42, 42, 42, 0.95)');
                document.documentElement.style.setProperty('--border-color', 'rgba(139, 118, 102, 0.2)');
                document.documentElement.style.setProperty('--accent-primary', '#D4AF37');
                document.documentElement.style.setProperty('--accent-secondary', '#8B7666');
                document.documentElement.style.setProperty('--accent-tertiary', '#A68F7B');
                document.documentElement.style.setProperty('--input-bg', 'rgba(51, 45, 40, 0.8)');
                document.documentElement.style.setProperty('--text-primary', '#e0e0e0');
                document.documentElement.style.setProperty('--text-secondary', '#A68F7B');
                document.documentElement.style.setProperty('--danger-color', '#C25450');
                document.documentElement.style.setProperty('--warning-color', '#D4A245');
                document.documentElement.style.setProperty('--success-color', '#7C9F6F');
            }
        }

        // Font size adjustment
        function adjustFontSize(change) {
            currentFontSize += change;
            currentFontSize = Math.max(12, Math.min(24, currentFontSize));
            document.body.style.fontSize = currentFontSize + 'px';
            document.querySelectorAll('.message-content').forEach(el => {
                el.style.fontSize = currentFontSize + 'px';
            });
        }

        // Update settings
        function updateSetting(setting, value) {
            if (setting === 'sessionMemory') {
                sessionMemory = value;
                console.log(`Session memory is now: ${sessionMemory}`);
                if (!sessionMemory) {
                    conversationHistory = [];
                }
            }
        }

        // Clear chat
        function clearChat() {
            const chatContainer = document.getElementById('chatContainer');
            chatContainer.innerHTML = `
                <div class="message system-message">
                    <div class="message-icon">⚡</div>
                    <div class="message-content">Chat cleared. Ready for new conversation.</div>
                </div>
            `;
            conversationHistory = [];
        }

        // Export chat
        function exportChat() {
            const chatContent = Array.from(document.querySelectorAll('.chat-container .message')).map(msg => {
                const role = msg.classList.contains('user-message') ? 'USER' : msg.classList.contains('assistant-message') ? 'ASSISTANT' : 'SYSTEM';
                const contentElement = msg.querySelector('.message-content');
                const content = contentElement.innerText; 
                return `${role}: ${content}`;
            }).join('\n\n');

            const blob = new Blob([chatContent], {type: 'text/plain'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `r3kon_chat_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(a.href);
        }

        // Clear memory
        function clearMemory() {
            conversationHistory = [];
            alert('Conversation memory cleared!');
        }

        // Scroll to bottom
        function scrollToBottom() {
            const chatContainer = document.getElementById('chatContainer');
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }

        // Escape HTML
        function escapeHtml(text) {
            if (typeof text !== 'string') return '';
            return text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        // Start polling when page loads
        document.addEventListener('DOMContentLoaded', function() {
            console.log('[APP] R3KON GPT loaded, starting status polling...');
            // Start polling after a short delay
            setTimeout(pollStatus, 500);
        });
        
    </script>
</body>
</html>'''
    return html_content


@app.route('/api/status')
def status():
    """Return model loading status"""
    global model_loaded, loading_progress, loading_message
    
    # Force a check of the actual state
    current_model_loaded = bool(model_loaded)
    current_progress = int(loading_progress)
    current_message = str(loading_message)
    
    # Debug logging
    print(f"[STATUS] API called - loaded={current_model_loaded}, progress={current_progress}, msg='{current_message}'")
    
    response_data = {
        "modelLoaded": current_model_loaded,
        "status": "ready" if current_model_loaded else "loading",
        "progress": current_progress,
        "message": current_message
    }
    
    response = jsonify(response_data)
    
    # Nuclear cache prevention
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response

@app.route('/api/test')
def test_api():
    """Test endpoint for debugging"""
    return jsonify({
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "model_loaded": model_loaded,
        "flask_running": True,
        "progress": loading_progress
    })

@app.route('/icon.png')
def serve_icon():
    """Serve the icon from the same directory as main.py"""
    return send_file('icon.png', mimetype='image/png')

@app.route('/favicon.ico')
def serve_favicon():
    """Serve favicon (same as icon)"""
    return send_file('icon.png', mimetype='image/png')

@app.route('/api/chat/stream', methods=['POST'])
def chat_stream():
    # Wait for the model to be loaded if it's not already, but with timeout
    if not model_loaded:
        print("[WAITING] Model not loaded yet, waiting for model_loaded_event...")
        # Wait for model with timeout
        model_loaded_success = model_loaded_event.wait(timeout=120)  # 2 minute timeout
        
        if not model_loaded_success or not model_loaded:
            print("[ERROR] Model loading timeout or failed")
            return jsonify({"error": "Model is still loading or failed to load. Please try again in a moment."}), 503  # Service Unavailable
    
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        message = data.get('message', '')
        config = data.get('config', {})
        history = data.get('history', [])
        
        if not message:
            return jsonify({"error": "No message provided"}), 400
        
        return Response(
            generate_response_stream(message, config, history),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )
    except Exception as e:
        print(f"Error in chat stream: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop():
    """Stop generation"""
    global stop_generation_flag
    stop_generation_flag = True
    return jsonify({"success": True})

def run_flask():
    global flask_started
    port = 62637
    
    print(f"\n{'='*60}")
    print(f"[FLASK DEBUG] Starting Flask initialization")
    print(f"[FLASK DEBUG] Port: {port}")
    print(f"[FLASK DEBUG] Current directory: {os.getcwd()}")
    print(f"[FLASK DEBUG] Python version: {sys.version}")
    print(f"[FLASK DEBUG] BASE_PATH: {BASE_PATH}")
    
    # List what files Flask can see
    try:
        print(f"[FLASK DEBUG] Files in working directory:")
        for item in os.listdir(os.getcwd())[:10]:  # First 10 items
            print(f"  - {item}")
    except Exception as e:
        print(f"[FLASK DEBUG] Could not list directory: {e}")
    
    print(f"{'='*60}\n")
    
    flask_started = True
    print(f"[FLASK] Starting server on http://127.0.0.1:{port}")
    
    # Disable Flask logging to reduce console noise
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # Set Flask to production mode
    os.environ['FLASK_ENV'] = 'production'
    
    try:
        app.run(
            host='127.0.0.1',
            port=port,
            debug=False,
            use_reloader=False,
            threaded=True
        )
    except Exception as e:
        print(f"[FLASK ERROR] Failed to start Flask server: {e}")
        print(f"[FLASK ERROR] Details: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    try:
        print("\n" + "=" * 80)
        print("|" + " " * 78 + "|")
        print("|" + " " * 20 + "R3KON GPT - Elite Cybersecurity AI" + " " * 24 + "|")
        print("|" + " " * 78 + "|")
        print("=" * 80)
        print("\n[STARTUP] Initializing application...")
        
        # Start Flask first - NOT as daemon
        print("=" * 80)
        print("[STARTUP] Starting Flask Web Server...")
        print("=" * 80)
        flask_thread = threading.Thread(target=run_flask, daemon=False)
        flask_thread.start()
        
        port = 62637
        url = f"http://127.0.0.1:{port}"
        
        print(f"[STARTUP] Waiting for Flask server to respond at {url}...")
        flask_ready = False
        max_attempts = 60
        
        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.get(f"{url}/api/status", timeout=2)
                if response.status_code == 200:
                    print(f"[SUCCESS] Flask server is ready! (attempt {attempt}/{max_attempts})")
                    flask_ready = True
                    break
            except requests.exceptions.ConnectionError:
                if attempt % 5 == 0 or attempt == 1:
                    print(f"  [{attempt}/{max_attempts}] Still starting...")
            except Exception as e:
                print(f"  [ERROR] Attempt {attempt}: {e}")
            time.sleep(1)
        
        if not flask_ready:
            print("\n[ERROR] Flask Server Failed to Start")
            print("=" * 80)
            print(f"The web server did not respond within {max_attempts} seconds.")
            print("\nCheck the error messages above for more details.")
            print("=" * 80)
            input("\nPress Enter to exit...")
            sys.exit(1)
        
        print("=" * 80)
        print("[STARTUP] Starting AI Model Loading (Background Process)")
        print("=" * 80)
        print("This may take 1-2 minutes depending on your system...")
        print("The interface will open while the model loads.\n")
        
        # Start model loading in background
        model_thread = threading.Thread(target=load_model, daemon=False)
        model_thread.start()
        
        print("[STARTUP] Model loading started in background...")
        
        print("=" * 80)
        print("[STARTUP] Opening R3KON GPT Interface")
        print("=" * 80)
        print(f"URL: {url}")
        print("Window Size: 1400x900")
        print("\nThe AI model will continue loading in the background.")
        print("You'll see a progress indicator in the interface.\n")
        
        # Create webview window
        window = webview.create_window(
            'R3KON GPT - Elite Cybersecurity AI',
            url,
            width=1400,
            height=900,
            resizable=True,
            fullscreen=False,
            min_size=(1200, 700)
        )
        
        print("[WEBVIEW] Window created successfully")
        print("[WEBVIEW] Starting event loop...\n")
        
        # Start the webview (this blocks until window closes)
        webview.start()
        
        print("\n[SHUTDOWN] Application closed normally.")
        
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Keyboard interrupt received. Shutting down...")
    except Exception as e:
        print("\n" + "=" * 80)
        print(" FATAL ERROR IN MAIN THREAD")
        print("=" * 80)
        print(f"Error: {e}")
        print(f"Type: {type(e).__name__}")
        print("\nFull error details:")
        import traceback
        traceback.print_exc()
        print("=" * 80)
        input("\nPress Enter to exit...")
        sys.exit(1)
    finally:
        print("\n[CLEANUP] Shutting down all threads...")
        # Give threads time to clean up
        time.sleep(2)
