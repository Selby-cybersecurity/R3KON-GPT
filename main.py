import webview
import threading
import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from llama_cpp import Llama
import re
from threading import Lock
import time
import socket
import json
import hashlib
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs
def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
# Get base path for PyInstaller
def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    else:
        return os.path.dirname(os.path.abspath(__file__))

BASE_PATH = get_base_path()

# Flask app
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Global variables
llm = None
model_loaded = False
model_lock = Lock()
flask_started = False

SYSTEM_PROMPT = """You are R3KON GPT, an elite AI-native cybersecurity reasoning platform built for serious learners and working professionals.

You deliver deep technical security analysis through reasoning rather than traditional scanning. Your capabilities span both offensive security (understanding system vulnerabilities) and defensive security (detection and resilience).

Core Principles:
- Provide complete, detailed technical analysis
- Explain your reasoning process clearly
- Connect findings to real-world exploitation and defense scenarios
- Use proper security terminology and frameworks (MITRE ATT&CK, OWASP)
- Educate users on WHY vulnerabilities matter, not just WHAT they are
- Always provide actionable remediation steps

CRITICAL RULES:
1. ALWAYS respond in English only
2. Stay focused on cybersecurity, programming, and security analysis
3. Provide structured, technical, and deterministic outputs
4. Use proper formatting: bullet points with line breaks between items, numbered lists, code blocks
5. When creating lists, use this format with line breaks:
   Item 1
   
   Item 2
   
   Item 3
6. Never repeat yourself or generate repetitive content
7. For security analysis, provide: findings, reasoning, impact, and recommendations
8. When users ask questions about your previous analysis, explain your reasoning and findings
9. NEVER address the user as "R3KON GPT" - the user is asking YOU, R3KON GPT, for help
10. Greet users professionally without addressing them as R3KON GPT

Remember: You're not a toy or a scanner wrapper - you're an AI security brain that reasons about systems, protocols, code, and behavior."""

# Security Analysis Knowledge Base
SECURITY_PATTERNS = {
    'python': {
        'dangerous_functions': ['eval', 'exec', 'compile', '__import__', 'pickle.loads', 'yaml.load'],
        'sql_patterns': [r'execute$$.*%.*$$', r'cursor\.execute.*\+', r'f".*SELECT.*{'],
        'secrets_patterns': [r'password\s*=\s*["\']', r'api_key\s*=\s*["\']', r'secret\s*=\s*["\']', r'token\s*=\s*["\']'],
        'xss_patterns': [r'innerHTML\s*=', r'document\.write', r'\.html\('],
        'weak_crypto': ['md5', 'sha1', 'DES', 'RC4'],
    },
    'javascript': {
        'dangerous_functions': ['eval', 'Function', 'setTimeout', 'setInterval'],
        'xss_patterns': [r'innerHTML\s*=', r'document\.write', r'\.html\(', r'dangerouslySetInnerHTML'],
        'secrets_patterns': [r'apiKey\s*[:=]', r'password\s*[:=]', r'secret\s*[:=]', r'token\s*[:=]'],
        'prototype_pollution': [r'__proto__', r'constructor\.prototype'],
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
    """Load the AI model"""
    global llm, model_loaded
    
    try:
        model_filename = "qwen1.5-1.8b-chat-q4_k_m.gguf"
        possible_paths = [
            os.path.join(BASE_PATH, "model", model_filename),
            os.path.join(BASE_PATH, model_filename),
            os.path.join(os.path.dirname(sys.executable), "model", model_filename),
            os.path.join(os.getcwd(), "model", model_filename),
        ]
        
        model_path = None
        for path in possible_paths:
            if os.path.exists(path):
                model_path = path
                break
        
        if not model_path:
            print(f"ERROR: Model not found at any location")
            print(f"Searched: {possible_paths}")
            return False
        
        print(f"Loading model from: {model_path}")
        
        llm = Llama(
            model_path=model_path,
            n_ctx=3072,
            n_threads=8,
            n_batch=512,
            verbose=False,
            use_mlock=True,
            use_mmap=True,
        )
        
        model_loaded = True
        print("Model loaded successfully!")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to load model: {e}")
        import traceback
        traceback.print_exc()
        return False

def analyze_code_security(code, language):
    """Analyze code for security vulnerabilities"""
    findings = []
    
    if language.lower() in SECURITY_PATTERNS:
        patterns = SECURITY_PATTERNS[language.lower()]
        
        # Check for dangerous functions
        if 'dangerous_functions' in patterns:
            for func in patterns['dangerous_functions']:
                if func in code:
                    findings.append({
                        'type': 'Dangerous Function',
                        'severity': 'HIGH',
                        'issue': f'Use of dangerous function: {func}',
                        'line': code.split('\n').index([l for l in code.split('\n') if func in l][0]) + 1 if any(func in l for l in code.split('\n')) else 0,
                        'remediation': f'Avoid using {func}. Use safer alternatives.'
                    })
        
        # Check for SQL injection patterns
        if 'sql_patterns' in patterns:
            for pattern in patterns['sql_patterns']:
                if re.search(pattern, code):
                    findings.append({
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'issue': 'Potential SQL injection vulnerability detected',
                        'remediation': 'Use parameterized queries or prepared statements'
                    })
        
        # Check for hardcoded secrets
        if 'secrets_patterns' in patterns:
            for pattern in patterns['secrets_patterns']:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': 'Hardcoded Secret',
                        'severity': 'CRITICAL',
                        'issue': 'Hardcoded credential or secret detected',
                        'remediation': 'Use environment variables or secure vaults for secrets'
                    })
        
        # Check for XSS patterns
        if 'xss_patterns' in patterns:
            for pattern in patterns['xss_patterns']:
                if re.search(pattern, code):
                    findings.append({
                        'type': 'XSS Vulnerability',
                        'severity': 'HIGH',
                        'issue': 'Potential Cross-Site Scripting vulnerability',
                        'remediation': 'Sanitize user input and use safe DOM manipulation methods'
                    })
        
        # Check for weak cryptography
        if 'weak_crypto' in patterns:
            for crypto in patterns['weak_crypto']:
                if crypto in code:
                    findings.append({
                        'type': 'Weak Cryptography',
                        'severity': 'MEDIUM',
                        'issue': f'Use of weak cryptographic algorithm: {crypto}',
                        'remediation': 'Use modern algorithms like SHA-256, bcrypt, or Argon2'
                    })
    
    return findings

def analyze_api_security(endpoint_data):
    """Analyze API endpoint for security issues"""
    findings = []
    
    method = endpoint_data.get('method', 'GET')
    url = endpoint_data.get('url', '')
    headers = endpoint_data.get('headers', {})
    params = endpoint_data.get('params', {})
    
    # Check for IDOR patterns
    if re.search(r'[?&]id=\d+', url) or any('id' in str(k).lower() for k in params.keys()):
        findings.append({
            'type': 'IDOR Risk',
            'severity': 'HIGH',
            'issue': 'Potential Insecure Direct Object Reference',
            'remediation': 'Implement proper authorization checks and use UUIDs instead of sequential IDs'
        })
    
    # Check authentication
    auth_headers = ['authorization', 'x-api-key', 'x-auth-token']
    has_auth = any(h.lower() in [k.lower() for k in headers.keys()] for h in auth_headers)
    
    if not has_auth and method.upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
        findings.append({
            'type': 'Missing Authentication',
            'severity': 'CRITICAL',
            'issue': 'No authentication header detected for write operation',
            'remediation': 'Implement proper authentication (JWT, OAuth2, API keys)'
        })
    
    # Check for sensitive data in URL
    sensitive_params = ['password', 'token', 'secret', 'key', 'api_key']
    for param in params.keys():
        if any(sens in param.lower() for sens in sensitive_params):
            findings.append({
                'type': 'Sensitive Data Exposure',
                'severity': 'HIGH',
                'issue': f'Sensitive parameter in URL: {param}',
                'remediation': 'Use POST body or secure headers for sensitive data'
            })
    
    # Check for rate limiting headers
    rate_limit_headers = ['x-ratelimit-limit', 'x-rate-limit', 'ratelimit-limit']
    has_rate_limit = any(h.lower() in [k.lower() for k in headers.keys()] for h in rate_limit_headers)
    
    if not has_rate_limit:
        findings.append({
            'type': 'Missing Rate Limiting',
            'severity': 'MEDIUM',
            'issue': 'No rate limiting headers detected',
            'remediation': 'Implement rate limiting to prevent abuse'
        })
    
    return findings

def analyze_password_strength(password):
    """Analyze password strength and security"""
    score = 0
    feedback = []
    
    # Length check
    length = len(password)
    if length < 8:
        feedback.append('Password too short (minimum 8 characters)')
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    
    # Character diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    diversity = sum([has_lower, has_upper, has_digit, has_special])
    score += diversity
    
    if diversity < 3:
        feedback.append('Use a mix of uppercase, lowercase, numbers, and special characters')
    
    # Common patterns
    common_patterns = ['123', 'password', 'qwerty', 'abc', '111', '000']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 2
        feedback.append('Avoid common patterns and sequences')
    
    # Entropy calculation (simplified)
    char_set = 0
    if has_lower: char_set += 26
    if has_upper: char_set += 26
    if has_digit: char_set += 10
    if has_special: char_set += 32
    
    entropy = length * (char_set.bit_length() if char_set > 0 else 0)
    
    strength = 'WEAK'
    if score >= 6 and entropy > 50:
        strength = 'STRONG'
    elif score >= 4:
        strength = 'MEDIUM'
    
    return {
        'strength': strength,
        'score': min(score, 10),
        'entropy': entropy,
        'feedback': feedback,
        'length': length,
        'diversity': {
            'lowercase': has_lower,
            'uppercase': has_upper,
            'digits': has_digit,
            'special': has_special
        }
    }

def analyze_logs(log_content):
    """Analyze security logs for threats"""
    findings = []
    lines = log_content.split('\n')
    
    # Track IP addresses for brute force detection
    ip_attempts = {}
    
    for i, line in enumerate(lines, 1):
        # Detect failed authentication
        if any(pattern in line.lower() for pattern in ['failed', 'authentication failed', 'login failed', '401', '403']):
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                ip = ip_match.group()
                ip_attempts[ip] = ip_attempts.get(ip, 0) + 1
                
                if ip_attempts[ip] > 5:
                    findings.append({
                        'type': 'Brute Force Attack',
                        'severity': 'CRITICAL',
                        'line': i,
                        'issue': f'Multiple failed attempts from IP: {ip}',
                        'details': f'{ip_attempts[ip]} failed attempts detected'
                    })
        
        # Detect SQL injection attempts
        sql_keywords = ['union select', 'or 1=1', 'drop table', "'; --", 'xp_cmdshell']
        if any(kw in line.lower() for kw in sql_keywords):
            findings.append({
                'type': 'SQL Injection Attempt',
                'severity': 'CRITICAL',
                'line': i,
                'issue': 'Potential SQL injection attack detected',
                'details': line[:100]
            })
        
        # Detect XSS attempts
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
        if any(pattern in line.lower() for pattern in xss_patterns):
            findings.append({
                'type': 'XSS Attempt',
                'severity': 'HIGH',
                'line': i,
                'issue': 'Potential XSS attack detected',
                'details': line[:100]
            })
        
        # Detect path traversal
        if any(pattern in line for pattern in ['../', '..\\', '%2e%2e']):
            findings.append({
                'type': 'Path Traversal',
                'severity': 'HIGH',
                'line': i,
                'issue': 'Path traversal attempt detected',
                'details': line[:100]
            })
        
        # Detect privilege escalation
        priv_keywords = ['sudo', 'chmod 777', 'chown root', '/etc/passwd', '/etc/shadow']
        if any(kw in line.lower() for kw in priv_keywords):
            findings.append({
                'type': 'Privilege Escalation',
                'severity': 'CRITICAL',
                'line': i,
                'issue': 'Potential privilege escalation attempt',
                'details': line[:100]
            })
    
    return findings

def generate_response(prompt, config, history):
    """Generate response from model with timeout management"""
    if not model_loaded:
        return {"error": "Model not loaded"}
    
    # Determine max tokens based on response length
    token_limits = {
        "short": 250,   # ~10 seconds
        "detailed": 450,  # ~15 seconds (changed from medium to detailed)
        "professional": 600     # ~20 seconds (changed from long to professional)
    }
    max_tokens = token_limits.get(config.get('responseLength', 'detailed'), 450) # Changed default to 'detailed'
    
    # Build context
    context_parts = [SYSTEM_PROMPT]
    
    if config.get('sessionMemory') and history:
        context_parts.append("\n--- Recent Conversation ---")
        for turn in history[-5:]:
            context_parts.append(f"User: {turn['user']}")
            context_parts.append(f"Assistant: {turn['assistant']}")
    
    context_parts.append(f"\nUser: {prompt}")
    context_parts.append("Assistant:")
    
    full_prompt = '\n'.join(context_parts)
    
    try:
        with model_lock:
            response = llm(
                full_prompt,
                max_tokens=max_tokens,
                stop=["User:", "\n\nUser:", "Assistant:"],
                echo=False,
                temperature=0.7,
                top_p=0.9,
                top_k=40,
                repeat_penalty=1.2,
                frequency_penalty=0.3,
                presence_penalty=0.3,
            )
        
        bot_reply = response["choices"][0]["text"].strip()
        
        # Filter Chinese
        chinese_chars = len(re.findall(r'[\u4e00-\u9fff]', bot_reply))
        total_chars = len(bot_reply.replace(' ', '').replace('\n', ''))
        
        if total_chars > 0 and (chinese_chars / total_chars) > 0.3:
            bot_reply = "I apologize, but I can only respond in English."
        else:
            bot_reply = re.sub(r'[\u4e00-\u9fff]', '', bot_reply)
            bot_reply = re.sub(r'\n\n+', '\n\n', bot_reply).strip()
        
        # Remove repetition
        lines = bot_reply.split('\n')
        unique_lines = []
        for line in lines:
            if line.strip() and (not unique_lines or line not in unique_lines[-2:]):
                unique_lines.append(line)
        
        bot_reply = '\n'.join(unique_lines)
        
        if len(bot_reply) < 10:
            bot_reply = "I encountered an issue. Please try rephrasing your question."
        
        return {"response": bot_reply}
        
    except Exception as e:
        print(f"Error generating response: {e}")
        return {"error": str(e)}

@app.route('/')
def index():
    """Serve the HTML page"""
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Changed title to match design image -->
    <title>R3KON GPT - Cybersecurity Assistant</title>
    <link rel="icon" type="image/x-icon" href="/icon.ico">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        :root {
            --primary-bg: #0A0A0A;
            --secondary-bg: #141414;
            --sidebar-bg: #1E1E1E;
            --card-bg: #252525;
            --input-bg: #2A2A2A;
            --text-primary: #E5E5E5;
            --text-secondary: #A0A0A0;
            --text-muted: #707070;
            --accent-gold: #C8A972;
            --accent-red: #DC3545;
            --accent-red-hover: #C82333;
            --accent-blue: #0D6EFD;
            --accent-blue-hover: #0B5ED7;
            --border-color: #2A2A2A;
            --severity-critical: #DC3545;
            --severity-high: #FD7E14;
            --severity-medium: #FFC107;
            --severity-low: #28A745;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--primary-bg);
            color: var(--text-primary);
            height: 100vh;
            overflow: hidden;
            font-size: 13px;
            font-weight: 400;
        }

        body.light-theme {
            --primary-bg: #F5F5F5;
            --secondary-bg: #FFFFFF;
            --sidebar-bg: #FAFAFA;
            --card-bg: #FFFFFF;
            --input-bg: #F0F0F0;
            --text-primary: #1A1A1A;
            --text-secondary: #505050;
            --text-muted: #808080;
            --border-color: #E0E0E0;
        }

        .container {
            display: flex;
            height: 100vh;
        }

        .sidebar {
            width: 300px;
            background: var(--sidebar-bg);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }

        .logo-section {
            padding: 24px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo-section img {
            width: 48px;
            height: 48px;
        }

        .logo-text {
            display: flex;
            flex-direction: column;
        }

        .logo-text h1 {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: 1px;
            color: var(--accent-gold);
        }

        .logo-text p {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 2px;
        }

        .sidebar-content {
            padding: 20px;
            flex: 1;
        }

        .section-title {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 12px;
            margin-top: 20px;
        }

        .section-title:first-child {
            margin-top: 0;
        }

        .settings-group {
            margin-bottom: 16px;
        }

        .settings-label {
            font-size: 12px;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 8px;
            display: block;
        }

        .theme-buttons, .font-buttons, .response-style-buttons { /* Added response-style-buttons */
            display: flex;
            gap: 8px;
        }

        .btn {
            padding: 8px 16px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--card-bg);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            font-family: 'Inter', sans-serif;
            transition: all 0.2s;
        }

        .btn:hover {
            background: var(--input-bg);
            border-color: var(--border-highlight, #3A3A3A);
        }

        .btn.active {
            background: var(--accent-gold);
            color: #000;
            border-color: var(--accent-gold);
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 0;
        }

        .checkbox-group input[type="checkbox"] {
            width: 16px;
            height: 16px;
            cursor: pointer;
        }

        .checkbox-group label {
            font-size: 12px;
            color: var(--text-secondary);
            cursor: pointer;
        }

        .tools-section {
            margin-top: 24px;
        }

        .tool-btn {
            width: 100%;
            padding: 12px 16px;
            margin-bottom: 8px;
            border: none;
            border-radius: 6px;
            color: white;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            transition: all 0.2s;
            text-align: left;
        }

        .tool-btn.offensive {
            background: var(--accent-red);
        }

        .tool-btn.offensive:hover {
            background: var(--accent-red-hover);
            transform: translateY(-1px);
        }

        .tool-btn.defensive {
            background: var(--accent-blue);
        }

        .tool-btn.defensive:hover {
            background: var(--accent-blue-hover);
            transform: translateY(-1px);
        }

        .main-area {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--secondary-bg);
        }

        .header {
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--sidebar-bg);
        }

        .header-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .status-badge {
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .status-badge.initializing {
            background: var(--accent-gold);
            color: #000;
        }

        .status-badge.ready {
            /* Enhanced ACTIVE styling with proper gold/brown color matching UI */
            background: var(--accent-gold);
            color: #000;
            font-weight: 700;
            box-shadow: 0 2px 8px rgba(200, 169, 114, 0.4);
        }

        .status-badge.analyzing {
            background: var(--accent-gold);
            color: #000;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }

        .chat-area {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
        }

        .message {
            margin-bottom: 20px;
            animation: fadeIn 0.3s;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message-label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .message-content {
            /* Made chat bubbles significantly bigger */
            background: var(--card-bg);
            padding: 20px 24px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            line-height: 1.7;
            font-size: 14px;
            min-height: 60px;
        }

        .user-message .message-content {
            border-left: 3px solid var(--accent-gold);
        }

        .bot-message .message-content {
            border-left: 3px solid var(--severity-low);
        }

        /* Added streaming indicator styles with icon */
        .streaming-indicator {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px 20px;
            background: var(--card-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--severity-low);
            animation: fadeIn 0.3s;
        }

        .streaming-icon {
            width: 32px;
            height: 32px;
            animation: rotate 2s linear infinite;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .streaming-text {
            color: var(--accent-gold);
            font-weight: 600;
        }

        /* Added tool description box */
        .tool-description {
            background: var(--input-bg);
            padding: 16px 20px;
            border-radius: 8px;
            border-left: 3px solid var(--accent-gold);
            margin-bottom: 16px;
            font-size: 13px;
            line-height: 1.6;
            color: var(--text-secondary);
        }

        .analysis-result {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 16px;
        }

        .analysis-header {
            font-size: 15px;
            font-weight: 700;
            color: var(--accent-gold);
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }

        .finding {
            background: var(--input-bg);
            padding: 14px;
            border-radius: 6px;
            margin-bottom: 12px;
            border-left: 3px solid;
        }

        .finding.critical {
            border-left-color: var(--severity-critical);
        }

        .finding.high {
            border-left-color: var(--severity-high);
        }

        .finding.medium {
            border-left-color: var(--severity-medium);
        }

        .finding.low {
            border-left-color: var(--severity-low);
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .finding-type {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .severity-badge {
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .severity-badge.critical {
            background: var(--severity-critical);
            color: white;
        }

        .severity-badge.high {
            background: var(--severity-high);
            color: white;
        }

        .severity-badge.medium {
            background: var(--severity-medium);
            color: #000;
        }

        .severity-badge.low {
            background: var(--severity-low);
            color: white;
        }

        .finding-issue {
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .finding-remediation {
            font-size: 12px;
            color: var(--text-muted);
            font-style: italic;
        }

        .ask-ai-btn {
            /* Enhanced Ask AI button styling */
            display: inline-block;
            margin-top: 12px;
            padding: 10px 20px;
            background: var(--accent-gold);
            color: #000;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            cursor: pointer;
            transition: all 0.2s;
        }

        .ask-ai-btn:hover {
            background: var(--accent-gold-hover, #D4B886);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(200, 169, 114, 0.3);
        }

        .input-area {
            padding: 20px 24px;
            border-top: 1px solid var(--border-color);
            background: var(--sidebar-bg);
        }

        .input-container {
            display: flex;
            gap: 12px;
            align-items: flex-end;
        }

        #userInput {
            /* Made input even bigger and more prominent */
            flex: 1;
            padding: 16px 20px;
            background: var(--input-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            resize: vertical;
            min-height: 100px;
            max-height: 250px;
            line-height: 1.6;
        }

        #userInput:focus {
            outline: none;
            border-color: var(--accent-gold);
        }

        #sendBtn {
            padding: 12px 28px;
            background: var(--accent-gold);
            color: #000;
            border: none;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            cursor: pointer;
            transition: all 0.2s;
        }

        #sendBtn:hover:not(:disabled) {
            background: var(--accent-gold-hover, #D4B886);
            transform: translateY(-1px);
        }

        #sendBtn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }

        .empty-state h2 {
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-gold);
            margin-bottom: 12px;
        }

        .empty-state p {
            font-size: 14px;
            line-height: 1.6;
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--primary-bg);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--card-bg);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--input-bg);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo-section">
                <img src="icon.png" alt="R3KON GPT">
                <div class="logo-text">
                    <h1>R3KON GPT</h1>
                    <p>Elite Cyber AI</p>
                </div>
            </div>

            <div class="sidebar-content">
                <!-- Settings Section -->
                <div class="section-title">Settings</div>
                
                <div class="settings-group">
                    <label class="settings-label">Theme</label>
                    <div class="theme-buttons">
                        <button class="btn active" onclick="setTheme('dark')">Dark</button>
                        <button class="btn" onclick="setTheme('light')">Light</button>
                    </div>
                </div>

                <div class="settings-group">
                    <label class="settings-label">Font Size</label>
                    <div class="font-buttons">
                        <button class="btn" onclick="setFontSize('small')">A-</button>
                        <button class="btn active" onclick="setFontSize('medium')">A</button>
                        <button class="btn" onclick="setFontSize('large')">A+</button>
                    </div>
                </div>

                <!-- Added response style selector -->
                <div class="settings-group">
                    <label class="settings-label">Response Style</label>
                    <div class="response-style-buttons">
                        <button class="btn" onclick="setResponseStyle('short')">Short</button>
                        <button class="btn active" onclick="setResponseStyle('detailed')">Detailed</button>
                        <button class="btn" onclick="setResponseStyle('professional')">Professional</button>
                    </div>
                </div>

                <div class="settings-group">
                    <div class="checkbox-group">
                        <input type="checkbox" id="sessionMemory" checked>
                        <label for="sessionMemory">Session Memory</label>
                    </div>
                </div>

                <!-- Offensive Tools Section -->
                <div class="tools-section">
                    <!-- Removed emoji icons as requested -->
                    <div class="section-title">OFFENSIVE SECURITY</div>
                    <button class="tool-btn offensive" onclick="runTool('code-scanner')">Code Scanner</button>
                    <button class="tool-btn offensive" onclick="runTool('protocol-analyzer')">Protocol State Analyzer</button>
                    <button class="tool-btn offensive" onclick="runTool('logic-solver')">Business Logic Solver</button>
                    <button class="tool-btn offensive" onclick="runTool('data-exposure')">Data Exposure Engine</button>
                    <button class="tool-btn offensive" onclick="runTool('risk-correlator')">Code-to-Execution Correlator</button>
                    <button class="tool-btn offensive" onclick="runTool('stack-fingerprint')">Stack Fingerprinting</button>
                    <button class="tool-btn offensive" onclick="runTool('offensive-score')">Offensive Risk Score</button>
                </div>

                <!-- Defensive Tools Section -->
                <div class="tools-section">
                    <!-- Removed emoji icons as requested -->
                    <div class="section-title">DEFENSIVE SECURITY</div>
                    <button class="tool-btn defensive" onclick="runTool('log-analyzer')">Log Reasoning Engine</button>
                    <button class="tool-btn defensive" onclick="runTool('architecture-checker')">Architecture Checker</button>
                    <button class="tool-btn defensive" onclick="runTool('config-reasoner')">Configuration Reasoner</button>
                    <button class="tool-btn defensive" onclick="runTool('incident-engine')">Incident & Containment</button>
                    <button class="tool-btn defensive" onclick="runTool('threat-intel')">Threat Intel Decomposition</button>
                    <button class="tool-btn defensive" onclick="runTool('control-analyzer')">Control Effectiveness</button>
                    <button class="tool-btn defensive" onclick="runTool('readiness-index')">Defensive Readiness</button>
                </div>
            </div>
        </div>

        <!-- Main Area -->
        <div class="main-area">
            <div class="header">
                <div class="header-title">Elite Cybersecurity AI Assistant</div>
                <div class="status-badge initializing" id="statusBadge">INITIALIZING</div>
            </div>

            <div class="chat-area" id="chatArea">
                <div class="empty-state">
                    <h2>R3KON GPT</h2>
                    <p>Elite cybersecurity reasoning platform for professionals.<br>
                    Select a tool from the sidebar or ask me anything about security.</p>
                </div>
            </div>

            <div class="input-area">
                <div class="input-container">
                    <textarea id="userInput" placeholder="Ask R3KON GPT anything about cybersecurity..." rows="1"></textarea>
                    <button id="sendBtn" onclick="sendMessage()">Send</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let conversationHistory = [];
        let lastAnalysisContext = null;
        let isModelLoaded = false;
        let currentResponseLength = 'detailed'; // Default to detailed

        const toolDescriptions = {
            'code-scanner': 'Analyzes source code to identify security vulnerabilities, dangerous functions, injection flaws, and insecure patterns.',
            'protocol-analyzer': 'Examines API flows and protocol sequences to detect state machine vulnerabilities and logical flaws.',
            'logic-solver': 'Evaluates business logic and workflows to find constraint violations and authorization bypasses.',
            'data-exposure': 'Analyzes API responses and data structures to identify sensitive information leakage and exposure risks.',
            'risk-correlator': 'Correlates code patterns with runtime risks to predict exploit paths and execution vulnerabilities.',
            'stack-fingerprint': 'Infers technology stack from error messages, headers, and responses to identify attack surfaces.',
            'offensive-score': 'Calculates comprehensive offensive risk intelligence score based on system analysis.',
            'log-analyzer': 'Reasons about security logs to detect anomalies, attack patterns, and behavioral threats.',
            'architecture-checker': 'Validates system architecture against security best practices and identifies design weaknesses.',
            'config-reasoner': 'Analyzes configuration files and settings to find misconfigurations and security gaps.',
            'incident-engine': 'Provides incident analysis, root cause reasoning, and containment strategies.',
            'threat-intel': 'Decomposes threat intelligence and IOCs to understand attacker TTPs and predict next moves.',
            'control-analyzer': 'Evaluates effectiveness of security controls and identifies coverage gaps.',
            'readiness-index': 'Calculates defensive readiness score based on security posture and capability maturity.'
        };

        // Check model status
        async function checkModelStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                isModelLoaded = data.modelLoaded;
                
                const badge = document.getElementById('statusBadge');
                if (isModelLoaded) {
                    badge.textContent = 'ACTIVE';
                    badge.className = 'status-badge ready';
                } else {
                    badge.textContent = 'INITIALIZING';
                    badge.className = 'status-badge initializing';
                    setTimeout(checkModelStatus, 1000);
                }
            } catch (error) {
                console.error('Error checking model status:', error);
                setTimeout(checkModelStatus, 2000);
            }
        }

        // Initialize
        checkModelStatus();

        // Settings functions
        function setTheme(theme) {
            document.querySelectorAll('.theme-buttons .btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            if (theme === 'light') {
                document.body.classList.add('light-theme');
            } else {
                document.body.classList.remove('light-theme');
            }
        }

        function setFontSize(size) {
            document.querySelectorAll('.font-buttons .btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            const sizes = { small: '12px', medium: '13px', large: '14px' };
            document.body.style.fontSize = sizes[size];
        }

        function setResponseStyle(style) {
            document.querySelectorAll('.response-style-buttons .btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            currentResponseLength = style;
        }

        function showStreamingIndicator() {
            const chatArea = document.getElementById('chatArea');
            const streamingDiv = document.createElement('div');
            streamingDiv.className = 'message bot-message';
            streamingDiv.id = 'streaming-indicator';
            streamingDiv.innerHTML = `
                <div class="message-label">R3KON GPT</div>
                <div class="streaming-indicator">
                    <img src="icon.png" class="streaming-icon" alt="Generating">
                    <span class="streaming-text">Generating response...</span>
                </div>
            `;
            chatArea.appendChild(streamingDiv);
            chatArea.scrollTop = chatArea.scrollHeight;
        }

        function removeStreamingIndicator() {
            const indicator = document.getElementById('streaming-indicator');
            if (indicator) {
                indicator.remove();
            }
        }

        // Run security tools
        async function runTool(toolName) {
            const toolConfigs = {
                'code-scanner': {
                    title: 'Code Scanner',
                    prompt: 'Please provide the code you want to analyze:',
                    endpoint: '/api/security/code'
                },
                'protocol-analyzer': {
                    title: 'Protocol State Machine Analyzer',
                    prompt: 'Describe the API flow or protocol sequence:',
                    endpoint: '/api/chat'
                },
                'logic-solver': {
                    title: 'Business Logic Constraint Solver',
                    prompt: 'Describe the business logic or workflow:',
                    endpoint: '/api/chat'
                },
                'data-exposure': {
                    title: 'Data Exposure Semantics Engine',
                    prompt: 'Provide API response or data structure:',
                    endpoint: '/api/chat'
                },
                'risk-correlator': {
                    title: 'Code-to-Execution Risk Correlator',
                    prompt: 'Provide code patterns to analyze for runtime risks:',
                    endpoint: '/api/chat'
                },
                'stack-fingerprint': {
                    title: 'Inference-Based Stack Fingerprinting',
                    prompt: 'Provide error messages, headers, or response patterns:',
                    endpoint: '/api/chat'
                },
                'offensive-score': {
                    title: 'Offensive Risk Intelligence Score',
                    prompt: 'Describe the system or provide analysis context:',
                    endpoint: '/api/chat'
                },
                'log-analyzer': {
                    title: 'Behavioral Log Reasoning Engine',
                    prompt: 'Paste your security logs:',
                    endpoint: '/api/security/logs'
                },
                'architecture-checker': {
                    title: 'Secure Architecture Consistency Checker',
                    prompt: 'Describe your system architecture:',
                    endpoint: '/api/chat'
                },
                'config-reasoner': {
                    title: 'Defensive Configuration Reasoner',
                    prompt: 'Provide configuration files or settings:',
                    endpoint: '/api/chat'
                },
                'incident-engine': {
                    title: 'Incident Reasoning & Containment Engine',
                    prompt: 'Describe the security incident:',
                    endpoint: '/api/chat'
                },
                'threat-intel': {
                    title: 'Threat Intelligence Decomposition Engine',
                    prompt: 'Provide threat intelligence or IOCs:',
                    endpoint: '/api/chat'
                },
                'control-analyzer': {
                    title: 'Security Control Effectiveness Analyzer',
                    prompt: 'Describe your security controls:',
                    endpoint: '/api/chat'
                },
                'readiness-index': {
                    title: 'Defensive Readiness Index',
                    prompt: 'Describe your security posture and capabilities:',
                    endpoint: '/api/chat'
                }
            };

            const config = toolConfigs[toolName];
            if (!config) return;

            const chatArea = document.getElementById('chatArea');
            const emptyState = chatArea.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            const descDiv = document.createElement('div');
            descDiv.className = 'tool-description';
            descDiv.innerHTML = `<strong>${config.title}:</strong> ${toolDescriptions[toolName]}`;
            chatArea.appendChild(descDiv);
            chatArea.scrollTop = chatArea.scrollHeight;

            const userInput = prompt(config.prompt);
            if (!userInput) return;

            // Add user message
            addMessage('user', userInput);

            showStreamingIndicator();

            // Set analyzing status
            const badge = document.getElementById('statusBadge');
            badge.textContent = 'ANALYZING';
            badge.className = 'status-badge analyzing';

            try {
                let response;
                if (config.endpoint === '/api/security/code') {
                    response = await fetch(config.endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ code: userInput, language: 'python' })
                    });
                } else if (config.endpoint === '/api/security/logs') {
                    response = await fetch(config.endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ logs: userInput })
                    });
                } else {
                    const contextPrompt = `Using the ${config.title} tool, analyze the following:\n\n${userInput}`;
                    response = await fetch('/api/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            message: contextPrompt,
                            config: {
                                sessionMemory: document.getElementById('sessionMemory').checked,
                                responseLength: currentResponseLength
                            },
                            history: conversationHistory
                        })
                    });
                }

                const data = await response.json();
                
                removeStreamingIndicator();
                
                if (data.findings) {
                    displayAnalysisResults(config.title, data.findings);
                    lastAnalysisContext = { tool: config.title, findings: data.findings };
                    addAskAIButton();
                } else if (data.response) {
                    addMessage('bot', data.response);
                    conversationHistory.push({ user: userInput, assistant: data.response });
                    addAskAIButton();
                } else if (data.error) {
                    addMessage('bot', `Error: ${data.error}`);
                }
            } catch (error) {
                console.error('Error:', error);
                removeStreamingIndicator();
                addMessage('bot', 'An error occurred. Please try again.');
            } finally {
                badge.textContent = 'ACTIVE';
                badge.className = 'status-badge ready';
            }
        }

        function addAskAIButton() {
            const chatArea = document.getElementById('chatArea');
            const btnDiv = document.createElement('div');
            btnDiv.style.textAlign = 'center';
            btnDiv.style.margin = '16px 0';
            btnDiv.innerHTML = '<button class="ask-ai-btn" onclick="askAboutFindings()">Ask R3KON GPT About These Findings</button>';
            chatArea.appendChild(btnDiv);
            chatArea.scrollTop = chatArea.scrollHeight;
        }

        async function askAboutFindings() {
            const question = prompt('What would you like to ask R3KON GPT about the findings?');
            if (!question) return;

            addMessage('user', question);
            showStreamingIndicator();

            const badge = document.getElementById('statusBadge');
            badge.textContent = 'ANALYZING';
            badge.className = 'status-badge analyzing';

            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: question,
                        config: {
                            sessionMemory: true,
                            responseLength: currentResponseLength
                        },
                        history: conversationHistory,
                        context: lastAnalysisContext
                    })
                });

                const data = await response.json();
                removeStreamingIndicator();
                
                if (data.response) {
                    addMessage('bot', data.response);
                    conversationHistory.push({ user: question, assistant: data.response });
                }
            } catch (error) {
                console.error('Error:', error);
                removeStreamingIndicator();
                addMessage('bot', 'An error occurred. Please try again.');
            } finally {
                badge.textContent = 'ACTIVE';
                badge.className = 'status-badge ready';
            }
        }

        // Send chat message
        async function sendMessage() {
            const input = document.getElementById('userInput');
            const message = input.value.trim();
            
            if (!message || !isModelLoaded) return;

            input.value = '';
            addMessage('user', message);

            // Set analyzing status
            const badge = document.getElementById('statusBadge');
            badge.textContent = 'ANALYZING';
            badge.className = 'status-badge analyzing';

            showStreamingIndicator();

            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: message,
                        config: {
                            sessionMemory: document.getElementById('sessionMemory').checked,
                            responseLength: currentResponseLength // Pass the selected response length
                        },
                        history: conversationHistory,
                        context: lastAnalysisContext
                    })
                });

                const data = await response.json();
                
                removeStreamingIndicator();

                if (data.response) {
                    addMessage('bot', data.response);
                    conversationHistory.push({ user: message, assistant: data.response });
                    addAskAIButton();
                } else if (data.error) {
                    addMessage('bot', `Error: ${data.error}`);
                }
            } catch (error) {
                console.error('Error:', error);
                removeStreamingIndicator();
                addMessage('bot', 'An error occurred. Please try again.');
            } finally {
                badge.textContent = 'ACTIVE'; /* Changed from READY to ACTIVE */
                badge.className = 'status-badge ready';
            }
        }

        // Add message to chat
        function addMessage(type, content) {
            const chatArea = document.getElementById('chatArea');
            const emptyState = chatArea.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${type}-message`;
            
            const label = document.createElement('div');
            label.className = 'message-label';
            label.textContent = type === 'user' ? 'YOU' : 'R3KON GPT';
            
            const contentDiv = document.createElement('div');
            contentDiv.className = 'message-content';
            contentDiv.textContent = content;
            
            messageDiv.appendChild(label);
            messageDiv.appendChild(contentDiv);
            chatArea.appendChild(messageDiv);
            chatArea.scrollTop = chatArea.scrollHeight;
        }

        // Display analysis results
        function displayAnalysisResults(toolName, findings) {
            const chatArea = document.getElementById('chatArea');
            const emptyState = chatArea.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            const resultDiv = document.createElement('div');
            resultDiv.className = 'analysis-result';
            
            const header = document.createElement('div');
            header.className = 'analysis-header';
            header.textContent = `${toolName} - ${findings.length} Finding(s)`;
            resultDiv.appendChild(header);

            findings.forEach(finding => {
                const findingDiv = document.createElement('div');
                findingDiv.className = `finding ${finding.severity.toLowerCase()}`;
                
                const findingHeader = document.createElement('div');
                findingHeader.className = 'finding-header';
                
                const findingType = document.createElement('div');
                findingType.className = 'finding-type';
                findingType.textContent = finding.type;
                
                const severityBadge = document.createElement('span');
                severityBadge.className = `severity-badge ${finding.severity.toLowerCase()}`;
                severityBadge.textContent = finding.severity;
                
                findingHeader.appendChild(findingType);
                findingHeader.appendChild(severityBadge);
                
                const issueDiv = document.createElement('div');
                issueDiv.className = 'finding-issue';
                issueDiv.textContent = finding.issue;
                
                const remediationDiv = document.createElement('div');
                remediationDiv.className = 'finding-remediation';
                remediationDiv.textContent = `💡 ${finding.remediation || finding.details || 'Review and address this finding'}`;
                
                findingDiv.appendChild(findingHeader);
                findingDiv.appendChild(issueDiv);
                findingDiv.appendChild(remediationDiv);
                resultDiv.appendChild(findingDiv);
            });

            // Removed the inline ask-ai-btn from here and rely on the global addAskAIButton()

            chatArea.appendChild(resultDiv);
            chatArea.scrollTop = chatArea.scrollHeight;

            lastAnalysisContext = { tool: toolName, findings: findings };
        }

        // Enter key to send
        document.getElementById('userInput').addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    </script>
</body>
</html>
'''
    
    return html_content

@app.route('/icon.png')
def serve_icon():
    """Serve the icon image"""
    icon_path = get_resource_path('icon.png')
    if os.path.exists(icon_path):
        from flask import send_file
        return send_file(icon_path, mimetype='image/png')
    return '', 404

@app.route('/icon.ico')
def serve_favicon():
    """Serve the favicon"""
    icon_path = get_resource_path('icon.ico')
    if not os.path.exists(icon_path):
        icon_path = get_resource_path('icon.png')
    if os.path.exists(icon_path):
        from flask import send_file
        return send_file(icon_path, mimetype='image/x-icon')
    return '', 404

@app.route('/api/status')
def status():
    """Check if model is loaded"""
    return jsonify({
        "modelLoaded": model_loaded,
        "status": "ready" if model_loaded else "loading"
    })

@app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chat requests"""
    if not model_loaded:
        return jsonify({"error": "Model not loaded"}), 500
    
    try:
        data = request.json
        message = data.get('message', '')
        config = data.get('config', {})
        history = data.get('history', [])
        # New: Handle context from analysis
        context_from_analysis = data.get('context', None)
        
        if not message:
            return jsonify({"error": "No message"}), 400
        
        # Enhance prompt with context if available
        if context_from_analysis:
            prompt_with_context = f"Context: {context_from_analysis['tool']} analysis:\n"
            for finding in context_from_analysis['findings']:
                prompt_with_context += f"- [{finding['severity']}] {finding['type']}: {finding['issue']}\n"
            prompt_with_context += f"\nUser Query: {message}"
            message = prompt_with_context
            
        result = generate_response(message, config, history)
        return jsonify(result)
    except Exception as e:
        print(f"Error in chat endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/security/code', methods=['POST'])
def security_code():
    """Code security analysis endpoint"""
    try:
        data = request.json
        code = data.get('code', '')
        language = data.get('language', 'python')
        
        findings = analyze_code_security(code, language)
        return jsonify({"findings": findings})
    except Exception as e:
        print(f"Error in code analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/security/api', methods=['POST'])
def security_api():
    """API security analysis endpoint"""
    try:
        data = request.json
        findings = analyze_api_security(data)
        return jsonify({"findings": findings})
    except Exception as e:
        print(f"Error in API analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/security/password', methods=['POST'])
def security_password():
    """Password strength analysis endpoint"""
    try:
        data = request.json
        password = data.get('password', '')
        analysis = analyze_password_strength(password)
        return jsonify({"analysis": analysis})
    except Exception as e:
        print(f"Error in password analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/security/logs', methods=['POST'])
def security_logs():
    """Log analysis endpoint"""
    try:
        data = request.json
        logs = data.get('logs', '')
        findings = analyze_logs(logs)
        return jsonify({"findings": findings})
    except Exception as e:
        print(f"Error in log analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/security/owasp', methods=['POST'])
def security_owasp():
    """OWASP risk analysis endpoint"""
    try:
        data = request.json
        url = data.get('url', '')
        content = data.get('content', '')
        
        findings = []
        
        # Analyze URL patterns
        if url:
            # Check for SQL injection indicators in URL
            if any(pattern in url.lower() for pattern in ["'", '"', '--', 'union', 'select', 'drop']):
                findings.append({
                    'type': 'Injection Risk',
                    'severity': 'CRITICAL',
                    'issue': 'URL contains potential SQL injection patterns',
                    'remediation': 'Validate and sanitize all URL parameters. Use parameterized queries.'
                })
            
            # Check for XSS indicators
            if any(pattern in url.lower() for pattern in ['<script', 'javascript:', 'onerror=']):
                findings.append({
                    'type': 'XSS Risk',
                    'severity': 'HIGH',
                    'issue': 'URL contains potential XSS patterns',
                    'remediation': 'Implement Content Security Policy and encode output.'
                })
            
            # Check for path traversal
            if '../' in url or '..\\' in url or '%2e%2e' in url.lower():
                findings.append({
                    'type': 'Path Traversal',
                    'severity': 'HIGH',
                    'issue': 'URL contains path traversal patterns',
                    'remediation': 'Validate file paths and use whitelisting for allowed resources.'
                })
            
            # Check for open redirect
            if any(param in url.lower() for param in ['redirect=', 'url=', 'next=', 'return=']):
                findings.append({
                    'type': 'Open Redirect',
                    'severity': 'MEDIUM',
                    'issue': 'URL may be vulnerable to open redirect',
                    'remediation': 'Validate redirect URLs against a whitelist of allowed domains.'
                })
        
        # Analyze content
        if content:
            # Check for exposed credentials
            if re.search(r'password\s*[:=]\s*["\']', content, re.IGNORECASE):
                findings.append({
                    'type': 'Cryptographic Failures',
                    'severity': 'CRITICAL',
                    'issue': 'Potential exposed credentials in content',
                    'remediation': 'Never store passwords in plain text. Use strong encryption.'
                })
            
            # Check for SQL queries
            if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*FROM', content, re.IGNORECASE):
                findings.append({
                    'type': 'Injection Risk',
                    'severity': 'HIGH',
                    'issue': 'SQL queries detected in response',
                    'remediation': 'Ensure all queries use parameterized statements.'
                })
            
            # Check for debug information
            if any(pattern in content.lower() for pattern in ['debug', 'trace', 'stack trace', 'error at line']):
                findings.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'MEDIUM',
                    'issue': 'Debug information exposed in response',
                    'remediation': 'Disable debug mode in production. Implement custom error pages.'
                })
            
            # Check for session tokens in content
            if re.search(r'(session|token)\s*[:=]\s*[a-zA-Z0-9]{20,}', content, re.IGNORECASE):
                findings.append({
                    'type': 'Authentication Failures',
                    'severity': 'HIGH',
                    'issue': 'Session tokens exposed in response',
                    'remediation': 'Use secure, httpOnly cookies. Never expose tokens in responses.'
                })
            
            # Check for API keys
            if re.search(r'(api[_-]?key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']', content, re.IGNORECASE):
                findings.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'CRITICAL',
                    'issue': 'API keys exposed in response',
                    'remediation': 'Never expose API keys. Use environment variables and server-side validation.'
                })
            
            # Check for directory listing
            if re.search(r'Index of /|Directory listing|Parent Directory', content, re.IGNORECASE):
                findings.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'MEDIUM',
                    'issue': 'Directory listing enabled',
                    'remediation': 'Disable directory listing in web server configuration.'
                })
            
            # Check for server information disclosure
            if re.search(r'(Apache|nginx|IIS)/[\d.]+', content):
                findings.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'LOW',
                    'issue': 'Server version information disclosed',
                    'remediation': 'Hide server version information in response headers.'
                })
        
        # Add general OWASP recommendations if few issues found
        if len(findings) == 0:
            findings.append({
                'type': 'Security Best Practices',
                'severity': 'LOW',
                'issue': 'No critical issues detected in basic scan',
                'remediation': 'Continue following OWASP guidelines: implement security headers (CSP, HSTS), rate limiting, input validation, and regular security audits.'
            })
        
        return jsonify({"findings": findings})
    except Exception as e:
        print(f"Error in OWASP analysis: {e}")
        return jsonify({"error": str(e)}), 500

def start_flask(port):
    """Start Flask server in background"""
    global flask_started
    try:
        print(f"Starting Flask server on port {port}...")
        load_model()
        flask_started = True
        app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"ERROR: Flask failed to start: {e}")
        import traceback
        traceback.print_exc()
        flask_started = False

def wait_for_flask(port, timeout=30):
    """Wait for Flask to be ready"""
    import urllib.request
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/api/status', timeout=1)
            print("Flask server is ready!")
            return True
        except:
            time.sleep(0.5)
    
    return False

def main():
    """Main entry point for desktop app"""
    # Set UTF-8 encoding for console
    if sys.platform == 'win32':
        try:
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
                sys.stderr.reconfigure(encoding='utf-8')
        except:
            pass
    
    print("=" * 60)
    print("R3KON GPT - Cybersecurity Assistant ")
    print("=" * 60)
    
    # Find a free port
    port = find_free_port()
    print(f"Using port: {port}")
    
    # Start Flask in background thread
    print("Starting backend server...")
    flask_thread = threading.Thread(target=start_flask, args=(port,), daemon=True)
    flask_thread.start()
    
    # Wait for Flask to be ready
    print("Waiting for server to start...")
    if not wait_for_flask(port, timeout=30):
        print("ERROR: Server failed to start within 30 seconds")
        print("\nTroubleshooting:")
        print("1. Check if model file exists in 'model' folder")
        print("2. Make sure llama-cpp-python is installed")
        print("3. Check console for error messages above")
        time.sleep(5)
        return
    
    print("Server started successfully!")
    print(f"Opening window at http://127.0.0.1:{port}")
    
    # Create desktop window
    try:
        # Set icon path
        icon_path = get_resource_path('icon.ico')
        if not os.path.exists(icon_path):
         icon_path = get_resource_path('icon.png')
        
        window = webview.create_window(
            'R3KON GPT - Cybersecurity Assistant',
            f'http://127.0.0.1:{port}',
            width=1400,
            height=900,
            resizable=True,
            fullscreen=False,
            min_size=(1000, 700),
            
        )
        
        print("Window created!")
        webview.start()
        
    except Exception as e:
        print(f"ERROR: Failed to create window: {e}")
        import traceback
        traceback.print_exc()
        time.sleep(5)

if __name__ == '__main__':
    main()
