"""
Advanced Phishing Detector Module
Contains the core detection logic and algorithms
"""

import re
import urllib.parse
import whois
import ssl
import socket
import requests
from datetime import datetime
import tldextract
from difflib import SequenceMatcher
import dns.resolver
from bs4 import BeautifulSoup
import joblib
import uuid
import os
import csv
import time
import warnings
warnings.filterwarnings('ignore')

class AdvancedPhishingDetector:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        self.suspicious_keywords = ['login', 'signin', 'verify', 'account', 'update', 'banking', 
                                   'secure', 'confirm', 'password', 'credential', 'oauth', 'authentication']
        
        # Garantir que o diretório data existe
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        self.trusted_domains = self.load_trusted_domains()
        self.known_phishing_domains = self.load_known_domains()
        
        self.ml_model, self.vectorizer, self.ml_loaded = self.load_ml_model()
        self.history_file = os.path.join(data_dir, "phishing_history.csv")
        self.init_history_file()
    
    def load_trusted_domains(self):
        """Carrega lista de domínios confiáveis conhecidos do arquivo"""
        trusted_file = os.path.join(self.data_dir, "trusted_domains.txt")
        trusted_domains = set()
        
        if os.path.exists(trusted_file):
            try:
                with open(trusted_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            trusted_domains.add(line.lower())
            except Exception as e:
                print(f"Erro ao carregar domínios confiáveis: {e}")
                # Se houver erro, retorna conjunto vazio
                return set()
        
        return trusted_domains
    
    def load_known_domains(self):
        """Carrega lista de domínios de phishing conhecidos do arquivo"""
        phishing_file = os.path.join(self.data_dir, "known_phishing_domains.txt")
        known_domains = set()
        
        if os.path.exists(phishing_file):
            try:
                with open(phishing_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            known_domains.add(line.lower())
            except Exception as e:
                print(f"Erro ao carregar domínios de phishing: {e}")
                # Se houver erro, retorna conjunto vazio
                return set()
        
        return known_domains
    
    def load_ml_model(self):
        """Carrega o modelo de machine learning se existir"""
        try:
            model_path = os.path.join(self.data_dir, "phishing_model.pkl")
            vectorizer_path = os.path.join(self.data_dir, "vectorizer.pkl")
            
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                model = joblib.load(model_path)
                vectorizer = joblib.load(vectorizer_path)
                return model, vectorizer, True
            else:
                print("Modelos de ML não encontrados. Executando sem ML.")
                return None, None, False
        except Exception as e:
            print(f"Erro ao carregar modelo: {e}")
            return None, None, False
    
    def init_history_file(self):
        """Inicializa o arquivo de histórico se não existir"""
        if not os.path.exists(self.history_file):
            with open(self.history_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'URL', 'Risk_Score', 'Risk_Level', 'Details'])
    
    def save_to_history(self, url, score, details):
        """Salva a verificação no histórico"""
        risk_level = "ALTO RISCO" if score >= 60 else "RISCO MODERADO" if score >= 30 else "BAIXO RISCO"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Simplificar detalhes para CSV
        details_str = " | ".join(details[:5])  # Limitar a 5 detalhes
        
        with open(self.history_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, url, score, risk_level, details_str])
    
    def get_history(self):
        """Obtém o histórico de verificações"""
        history = []
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    history.append(row)
        return history
    
    def check_google_safe_browsing(self, url):
        """Verifica a URL usando a API do Google Safe Browsing (simulada)"""
        # Em uma implementação real, você precisaria de uma chave API
        time.sleep(0.1)  # Simular tempo de requisição
        
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Verificar se é um domínio confiável
        if self.is_trusted_domain(domain):
            return {"threats": [], "status": "SAFE"}
        
        # Simular detecção baseada em padrões comuns de phishing
        if any(keyword in url.lower() for keyword in ['login', 'verify', 'account', 'secure', 'bank']):
            return {"threats": ["SOCIAL_ENGINEERING"], "status": "UNSAFE"}
        else:
            return {"threats": [], "status": "SAFE"}
    
    def check_virustotal(self, url):
        """Verifica a URL usando a API do VirusTotal (simulada)"""
        time.sleep(0.1)  # Simular tempo de requisição
        
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Verificar se é um domínio confiável
        if self.is_trusted_domain(domain):
            return {"positives": 0, "total": 65, "permalink": ""}
        
        # Simular detecção baseada em padrões
        if domain and any(char in domain for char in ['-', '_']) and domain.count('.') > 1:
            return {"positives": 3, "total": 65, "permalink": f"https://www.virustotal.com/gui/url/{uuid.uuid4()}"}
        else:
            return {"positives": 0, "total": 65, "permalink": ""}
    
    def extract_url_features(self, url):
        features = {}
        
        # Comprimento da URL
        features['length'] = len(url)
        
        # Presença de IP no hostname
        parsed_url = urllib.parse.urlparse(url)
        features['has_ip'] = 1 if self.ip_pattern.match(parsed_url.netloc) else 0
        
        # Quantidade de subdomínios
        extracted = tldextract.extract(url)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # Presença de caracteres suspeitos
        features['has_@'] = 1 if '@' in url else 0
        features['has_hyphen'] = 1 if '-' in parsed_url.netloc else 0
        features['has_redirect'] = 1 if '//' in url[7:] else 0  # Verificar redirecionamentos após http://
        
        # Encurtamento de URL
        features['is_shortened'] = 1 if any(service in url for service in 
                                          ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly']) else 0
        
        # Presença de termos suspeitos
        features['suspicious_terms'] = sum(1 for keyword in self.suspicious_keywords if keyword in url.lower())
        
        return features
    
    def check_ssl_certificate(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verificar validade do certificado
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_valid = (not_after - datetime.now()).days
                    
                    # Verificar emissor
                    issuer = ""
                    if isinstance(cert['issuer'], tuple):
                        issuer = dict(x[0] for x in cert['issuer']).get('organizationName', '')
                    else:
                        issuer = cert['issuer'].get('organizationName', '')
                    
                    return {
                        'has_ssl': True,
                        'days_valid': days_valid,
                        'issuer': issuer
                    }
        except:
            return {'has_ssl': False, 'days_valid': 0, 'issuer': ''}
    
    def check_domain_age(self, domain):
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.now() - creation_date).days
                return max(age_days, 0)
        except:
            pass
        return 0
    
    def check_dns_records(self, domain):
        """Verifica os registros DNS do domínio"""
        record_types = ['A', 'MX', 'TXT', 'NS']
        records = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(r) for r in answers]
            except:
                records[record_type] = []
        
        return records
    
    def check_similarity_to_known(self, domain):
        max_similarity = 0
        for known_domain in self.known_phishing_domains:
            similarity = SequenceMatcher(None, domain, known_domain).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
        return max_similarity
    
    def analyze_content(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            content = response.text.lower()
            soup = BeautifulSoup(content, 'html.parser')
            
            # Verificar formulários
            form_count = len(soup.find_all('form'))
            
            # Verificar campos sensíveis
            sensitive_keywords = ['password', 'creditcard', 'cvv', 'ssn', 'social security', 'card number']
            sensitive_fields = 0
            for input_field in soup.find_all('input'):
                input_type = input_field.get('type', '').lower()
                input_name = input_field.get('name', '').lower()
                input_id = input_field.get('id', '').lower()
                
                if input_type == 'password':
                    sensitive_fields += 1
                elif any(keyword in input_name for keyword in sensitive_keywords):
                    sensitive_fields += 1
                elif any(keyword in input_id for keyword in sensitive_keywords):
                    sensitive_fields += 1
            
            # Verificar se é uma página de login
            is_login_page = any(term in content for term in ['log in', 'sign in', 'login', 'signin'])
            
            # Verificar presença de iframes
            iframe_count = len(soup.find_all('iframe'))
            
            # Verificar scripts externos
            script_count = len(soup.find_all('script', src=True))
            
            # Verificar meta tags suspeitas
            meta_refresh = len(soup.find_all('meta', attrs={'http-equiv': 'refresh'}))
            
            return {
                'form_count': form_count,
                'sensitive_fields': sensitive_fields,
                'is_login_page': is_login_page,
                'iframe_count': iframe_count,
                'script_count': script_count,
                'meta_refresh': meta_refresh,
                'status_code': response.status_code
            }
        except:
            return {
                'form_count': 0,
                'sensitive_fields': 0,
                'is_login_page': False,
                'iframe_count': 0,
                'script_count': 0,
                'meta_refresh': 0,
                'status_code': 0
            }
    
    def is_trusted_domain(self, domain):
        """Verifica se o domínio está na lista de confiáveis"""
        domain = domain.lower()
        for trusted_domain in self.trusted_domains:
            if trusted_domain in domain:
                return True
        return False
    
    def calculate_risk_score(self, url):
        score = 0
        details = []
        
        # Extrair domínio primeiro para verificar se é confiável
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Se for um domínio confiável, reduzir significativamente a pontuação
        if self.is_trusted_domain(domain):
            score -= 40  # Reduzir pontuação para domínios confiáveis
            details.append("Domínio confiável conhecido (pontuação reduzida)")
        
        # Extrair características da URL
        url_features = self.extract_url_features(url)
        
        # Análise baseada no comprimento da URL
        if url_features['length'] > 75:
            score += 10
            details.append("URL muito longa (suspeito)")
        
        # Verificar se contém IP
        if url_features['has_ip']:
            score += 30
            details.append("URL contém endereço IP (muito suspeito)")
        
        # Verificar múltiplos subdomínios
        if url_features['subdomain_count'] > 2:
            score += 15
            details.append(f"Muitos subdomínios ({url_features['subdomain_count']})")
        
        # Verificar caracteres suspeitos
        if url_features['has_@']:
            score += 25
            details.append("URL contém '@' (muito suspeito)")
        
        if url_features['has_hyphen']:
            score += 5
            details.append("Domínio contém hífen")
        
        if url_features['has_redirect']:
            score += 10
            details.append("Possui redirecionamento suspeito")
        
        if url_features['is_shortened']:
            score += 20
            details.append("URL encurtada (suspeito)")
        
        # Termos suspeitos
        if url_features['suspicious_terms'] > 0:
            score += url_features['suspicious_terms'] * 5
            details.append(f"Contém {url_features['suspicious_terms']} termo(s) suspeito(s)")
        
        # Verificar certificado SSL
        ssl_info = self.check_ssl_certificate(domain)
        if not ssl_info['has_ssl']:
            score += 30
            details.append("Site não possui certificado SSL (muito suspeito)")
        else:
            if ssl_info['days_valid'] < 30:
                score += 10
                details.append("Certificado SSL expirando em breve")
            
            # Verificar se o emissor é confiável
            trusted_issuers = ['digicert', 'comodo', 'symantec', 'go daddy', 'globalsign', 'entrust', 'lets encrypt']
            issuer = ssl_info['issuer'].lower()
            if not any(trusted in issuer for trusted in trusted_issuers):
                score += 5
                details.append(f"Emissor do certificado não é dos mais confiáveis: {ssl_info['issuer']}")
        
        # Verificar idade do domínio
        domain_age = self.check_domain_age(domain)
        if domain_age < 30:
            score += 25
            details.append(f"Domínio muito novo ({domain_age} dias)")
        elif domain_age < 365:
            score += 10
            details.append(f"Domínio relativamente novo ({domain_age} dias)")
        
        # Verificar similaridade com domínios conhecidos
        similarity = self.check_similarity_to_known(domain)
        if similarity > 0.8:
            score += 40
            details.append(f"Similaridade alta com domínio de phishing conhecido ({similarity:.2f})")
        elif similarity > 0.6:
            score += 20
            details.append(f"Similaridade moderada com domínio de phishing conhecido ({similarity:.2f})")
        
        # Verificar registros DNS
        dns_records = self.check_dns_records(domain)
        if not dns_records['A']:
            score += 15
            details.append("Domínio não possui registros A (suspeito)")
        
        # Análise de conteúdo
        content_info = self.analyze_content(url)
        if content_info['form_count'] > 0:
            score += 10
            details.append(f"Página contém {content_info['form_count']} formulário(s)")
        
        if content_info['sensitive_fields'] > 0:
            score += 25
            details.append(f"Página solicita {content_info['sensitive_fields']} campo(s) sensível(eis)")
        
        if content_info['is_login_page']:
            score += 15
            details.append("Página parece ser de login")
        
        if content_info['iframe_count'] > 3:
            score += 10
            details.append(f"Muitos iframes na página ({content_info['iframe_count']})")
        
        if content_info['meta_refresh'] > 0:
            score += 20
            details.append("Página contém redirecionamento automático (meta refresh)")
        
        # Verificação com Google Safe Browsing (simulado)
        safe_browsing = self.check_google_safe_browsing(url)
        if safe_browsing['threats']:
            score += 40
            details.append(f"Google Safe Browsing detectou ameaças: {', '.join(safe_browsing['threats'])}")
        
        # Verificação com VirusTotal (simulado)
        virustotal = self.check_virustotal(url)
        if virustotal['positives'] > 0:
            score += virustotal['positives'] * 5
            details.append(f"VirusTotal detectou {virustotal['positives']} motores como maliciosos")
        
        # Usar modelo de ML se disponível
        if self.ml_loaded:
            try:
                url_vectorized = self.vectorizer.transform([url])
                ml_prediction = self.ml_model.predict_proba(url_vectorized)[0][1]
                ml_score = int(ml_prediction * 50)  # Converter para escala 0-50
                score += ml_score
                details.append(f"Modelo ML detectou {ml_score} pontos de risco")
            except Exception as e:
                details.append(f"Erro no modelo ML: {str(e)}")
        
        # Garantir que a pontuação não ultrapasse 100 nem seja negativa
        score = max(0, min(score, 100))
        
        return score, details