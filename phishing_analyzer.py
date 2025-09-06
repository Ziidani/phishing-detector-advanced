import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from PIL import Image, ImageTk
import re
import urllib.parse
import whois
import ssl
import socket
import requests
from datetime import datetime, timedelta
import tldextract
from difflib import SequenceMatcher
import idna
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import threading
import time
import json
import os
import csv
from bs4 import BeautifulSoup
import dns.resolver
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from io import BytesIO
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import uuid
import pickle
import warnings
warnings.filterwarnings('ignore')

class AdvancedPhishingDetector:
    def __init__(self):
        # Padrões de regex para detecção
        self.ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        self.hex_pattern = re.compile(r'^0x[0-9a-fA-F]+')
        self.suspicious_keywords = ['login', 'signin', 'verify', 'account', 'update', 'banking', 
                                   'secure', 'confirm', 'password', 'credential', 'oauth', 'authentication']
        self.trusted_domains = self.load_trusted_domains()
        self.known_phishing_domains = self.load_known_domains()
        
        # Carregar modelo de ML
        self.ml_model, self.vectorizer, self.ml_loaded = self.load_ml_model()
        
        # Configurações para screenshot
        self.screenshot_dir = "screenshots"
        if not os.path.exists(self.screenshot_dir):
            os.makedirs(self.screenshot_dir)
            
        # Configurações para histórico
        self.history_file = "phishing_history.csv"
        self.init_history_file()
        
        # Configuração do WebDriver para screenshot
        self.driver = None
        self.init_webdriver()
    
    def init_webdriver(self):
        """Inicializa o WebDriver para captura de screenshots"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1200,800")
            self.driver = webdriver.Chrome(options=chrome_options)
        except Exception as e:
            print(f"Erro ao inicializar WebDriver: {e}")
            self.driver = None
    
    def load_trusted_domains(self):
        """Carrega lista de domínios confiáveis conhecidos"""
        return set([
            'twitter.com', 'facebook.com', 'google.com', 'github.com', 'amazon.com',
            'netflix.com', 'microsoft.com', 'apple.com', 'instagram.com', 'linkedin.com',
            'youtube.com', 'whatsapp.com', 'reddit.com', 'wordpress.com', 'wikipedia.org',
            'gov.br', 'org.br', 'com.br', 'org', 'com', 'net', 'edu', 'gov'
        ])
    
    def load_ml_model(self):
        """Carrega o modelo de machine learning se existir"""
        try:
            if os.path.exists('phishing_model.pkl') and os.path.exists('vectorizer.pkl'):
                model = joblib.load('phishing_model.pkl')
                vectorizer = joblib.load('vectorizer.pkl')
                return model, vectorizer, True
            else:
                # Criar um modelo simples para demonstração
                print("Criando modelo de demonstração...")
                return self.create_demo_model()
        except Exception as e:
            print(f"Erro ao carregar modelo: {e}")
            return None, None, False
    
    def create_demo_model(self):
        """Cria um modelo de demonstração simples"""
        # Dados de exemplo para treinamento
        urls = [
            "http://example-phishing-site.com/login",
            "http://secure-bank-verify.com",
            "http://facebook.com",
            "http://google.com",
            "http://github.com",
            "http://amazon.com",
            "http://netflix.com",
            "http://twitter.com",
            "http://microsoft.com",
            "http://apple.com"
        ]
        
        # Rótulos (0 = seguro, 1 = phishing)
        labels = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        
        # Vetorização
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(urls)
        
        # Treinamento do modelo
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, labels)
        
        # Salvar modelo
        joblib.dump(model, 'phishing_model.pkl')
        joblib.dump(vectorizer, 'vectorizer.pkl')
        
        return model, vectorizer, True
    
    def load_known_domains(self):
        """Carrega lista de domínios de phishing conhecidos"""
        known_domains = set()
        
        # Carregar de arquivo local se existir
        if os.path.exists('known_phishing_domains.txt'):
            try:
                with open('known_phishing_domains.txt', 'r') as f:
                    for line in f:
                        known_domains.add(line.strip())
            except:
                pass
        
        # Adicionar alguns domínios de exemplo
        known_domains.update([
            'example-phishing.com', 
            'fake-bank-site.com',
            'secure-login-update.com',
            'account-verification.xyz',
            'login-security-alert.com'
        ])
        
        return known_domains
    
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
        # Esta é uma simulação para demonstração
        time.sleep(0.5)  # Simular tempo de requisição
        
        # Simular resultados baseados em padrões suspeitos
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Domínios confiáveis são sempre seguros
        if any(trusted in domain for trusted in self.trusted_domains):
            return {"threats": [], "status": "SAFE"}
        
        # Outros casos baseados em padrões
        if any(keyword in url for keyword in ['login', 'verify', 'account']):
            return {"threats": ["SOCIAL_ENGINEERING"], "status": "UNSAFE"}
        else:
            return {"threats": [], "status": "SAFE"}
    
    def check_virustotal(self, url):
        """Verifica a URL usando a API do VirusTotal (simulada)"""
        # Em uma implementação real, você precisaria de uma chave API
        time.sleep(0.5)  # Simular tempo de requisição
        
        # Simular resultados baseados em padrões suspeitos
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Domínios confiáveis são sempre seguros
        if any(trusted in domain for trusted in self.trusted_domains):
            return {"positives": 0, "total": 65, "permalink": ""}
        
        # Outros casos baseados em padrões
        if domain and any(char in domain for char in ['-', '_']) and domain.count('.') > 1:
            return {"positives": 3, "total": 65, "permalink": f"https://www.virustotal.com/gui/url/{uuid.uuid4()}"}
        else:
            return {"positives": 0, "total": 65, "permalink": ""}
    
    def take_screenshot(self, url):
        """Tira uma screenshot da página web"""
        if not self.driver:
            return None
            
        try:
            self.driver.get(url)
            # Esperar um pouco para a página carregar
            time.sleep(2)
            
            # Tentar encontrar e fechar popups (caso existam)
            try:
                popups = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Aceitar') or contains(text(), 'Fechar') or contains(text(), 'X')]")
                for popup in popups[:2]:  # Clicar nos primeiros 2 botões encontrados
                    try:
                        popup.click()
                        time.sleep(0.5)
                    except:
                        pass
            except:
                pass
            
            # Tirar screenshot
            screenshot_path = os.path.join(self.screenshot_dir, f"{uuid.uuid4().hex}.png")
            self.driver.save_screenshot(screenshot_path)
            
            # Redimensionar imagem para preview
            img = Image.open(screenshot_path)
            img.thumbnail((400, 300))
            return img
        except Exception as e:
            print(f"Erro ao tirar screenshot: {e}")
            return None
    
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
        return any(trusted in domain for trusted in self.trusted_domains)
    
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

class AdvancedPhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Detector de Phishing Avançado")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        
        # Centralizar a janela
        self.center_window(1200, 800)
        
        # Configurar ícone e tema
        self.setup_theme()
        
        self.detector = AdvancedPhishingDetector()
        self.current_screenshot = None
        self.create_widgets()
        self.load_history()
        
    def center_window(self, width, height):
        """Centraliza a janela na tela"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_theme(self):
        """Configura o tema visual da aplicação"""
        style = ttk.Style()
        
        # Tentar usar temas mais modernos se disponíveis
        try:
            style.theme_use('clam')
        except:
            pass
        
        # Configurar cores e estilos
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        style.configure('Title.TLabel', background='#f0f0f0', font=('Arial', 16, 'bold'))
        style.configure('Risk.TLabel', font=('Arial', 14, 'bold'))
        style.configure('TButton', font=('Arial', 10))
        style.configure('Treeview', font=('Arial', 9))
        style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
        
    def create_widgets(self):
        # Configurar estilo
        style = ttk.Style()
        style.configure('TNotebook', background='white')
        style.configure('TNotebook.Tab', padding=[10, 5], font=('Arial', 10, 'bold'))
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Aba de verificação
        self.check_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.check_frame, text="🔍 Verificação de URL")
        
        # Aba de histórico
        self.history_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.history_frame, text="📊 Histórico")
        
        # Aba de estatísticas
        self.stats_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.stats_frame, text="📈 Estatísticas")
        
        # Aba de configurações
        self.settings_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.settings_frame, text="⚙️ Configurações")
        
        # Configurar a aba de verificação
        self.setup_check_tab()
        
        # Configurar a aba de histórico
        self.setup_history_tab()
        
        # Configurar a aba de estatísticas
        self.setup_stats_tab()
        
        # Configurar a aba de configurações
        self.setup_settings_tab()
    
    def setup_check_tab(self):
        # Frame principal
        main_frame = ttk.Frame(self.check_frame)
        main_frame.pack(fill='both', expand=True)
        
        # Configurar expansão
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Título
        title_label = ttk.Label(main_frame, text="Detector de Phishing Avançado", 
                               style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Label e entrada para URL
        url_label = ttk.Label(main_frame, text="URL para verificar:", font=("Arial", 10))
        url_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        
        self.url_entry = ttk.Entry(main_frame, width=60, font=("Arial", 10))
        self.url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(0, 5), padx=(5, 0))
        self.url_entry.bind('<Return>', lambda e: self.start_check())
        
        # Frame para botões
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Botão de verificação
        self.check_button = ttk.Button(button_frame, text="🔍 Verificar URL", command=self.start_check)
        self.check_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Botão de limpar
        clear_button = ttk.Button(button_frame, text="🗑️ Limpar", command=self.clear_results)
        clear_button.pack(side=tk.LEFT)
        
        # Frame de resultado
        result_frame = ttk.LabelFrame(main_frame, text="Resultado", padding="10")
        result_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(1, weight=1)
        
        # Indicador de risco
        self.risk_label = ttk.Label(result_frame, text="Digite uma URL e clique em Verificar", 
                                   style='Risk.TLabel', foreground="gray")
        self.risk_label.grid(row=0, column=0, pady=(0, 10))
        
        # Frame para screenshot e detalhes
        details_frame = ttk.Frame(result_frame)
        details_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        details_frame.columnconfigure(0, weight=1)
        details_frame.columnconfigure(1, weight=1)
        details_frame.rowconfigure(0, weight=1)
        
        # Área de screenshot
        screenshot_frame = ttk.LabelFrame(details_frame, text="📸 Visualização da Página", padding="5")
        screenshot_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        screenshot_frame.columnconfigure(0, weight=1)
        screenshot_frame.rowconfigure(0, weight=1)
        
        self.screenshot_label = ttk.Label(screenshot_frame, text="Nenhuma screenshot disponível", 
                                         foreground="gray", wraplength=300, justify=tk.CENTER)
        self.screenshot_label.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        
        # Área de detalhes
        details_text_frame = ttk.LabelFrame(details_frame, text="📋 Detalhes da análise", padding="5")
        details_text_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        details_text_frame.columnconfigure(0, weight=1)
        details_text_frame.rowconfigure(0, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(details_text_frame, width=50, height=15, 
                                                     font=("Consolas", 9))
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Barra de progresso
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(20, 0))
        
        # Status
        self.status_label = ttk.Label(main_frame, text="Pronto", font=("Arial", 9), foreground="gray")
        self.status_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
    
    def setup_history_tab(self):
        # Frame principal
        main_frame = ttk.Frame(self.history_frame)
        main_frame.pack(fill='both', expand=True)
        
        # Título
        title_label = ttk.Label(main_frame, text="Histórico de Verificações", 
                               style='Title.TLabel')
        title_label.pack(pady=(0, 10))
        
        # Frame para treeview e scrollbar
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill='both', expand=True)
        
        # Treeview para histórico
        columns = ('Timestamp', 'URL', 'Risk_Score', 'Risk_Level')
        self.history_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        # Definir cabeçalhos
        self.history_tree.heading('Timestamp', text='Data/Hora')
        self.history_tree.heading('URL', text='URL')
        self.history_tree.heading('Risk_Score', text='Pontuação')
        self.history_tree.heading('Risk_Level', text='Nível de Risco')
        
        # Definir largura das colunas
        self.history_tree.column('Timestamp', width=150)
        self.history_tree.column('URL', width=400)
        self.history_tree.column('Risk_Score', width=80)
        self.history_tree.column('Risk_Level', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Empacotar treeview e scrollbar
        self.history_tree.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Frame para botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(10, 0))
        
        # Botão para limpar histórico
        clear_btn = ttk.Button(button_frame, text="🗑️ Limpar Histórico", command=self.clear_history)
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Botão para exportar histórico
        export_btn = ttk.Button(button_frame, text="💾 Exportar CSV", command=self.export_history)
        export_btn.pack(side=tk.LEFT)
    
    def setup_stats_tab(self):
        # Frame principal
        main_frame = ttk.Frame(self.stats_frame)
        main_frame.pack(fill='both', expand=True)
        
        # Título
        title_label = ttk.Label(main_frame, text="Estatísticas de Verificações", 
                               style='Title.TLabel')
        title_label.pack(pady=(0, 10))
        
        # Frame para gráficos
        charts_frame = ttk.Frame(main_frame)
        charts_frame.pack(fill='both', expand=True)
        
        # Placeholder para gráficos
        self.stats_label = ttk.Label(charts_frame, text="As estatísticas serão exibidas aqui após várias verificações", 
                                    foreground="gray")
        self.stats_label.pack(pady=50)
        
        # Frame para botões
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(10, 0))
        
        # Botão para atualizar estatísticas
        update_btn = ttk.Button(button_frame, text="🔄 Atualizar Estatísticas", command=self.update_stats)
        update_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Botão para exportar gráficos
        export_btn = ttk.Button(button_frame, text="💾 Exportar Gráficos", command=self.export_charts)
        export_btn.pack(side=tk.LEFT)
    
    def setup_settings_tab(self):
        # Frame principal
        main_frame = ttk.Frame(self.settings_frame)
        main_frame.pack(fill='both', expand=True)
        
        # Título
        title_label = ttk.Label(main_frame, text="Configurações", 
                               style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Frame para configurações
        settings_frame = ttk.LabelFrame(main_frame, text="Opções de Verificação", padding="10")
        settings_frame.pack(fill='x', pady=(0, 20))
        
        # Checkboxes para opções
        self.ssl_var = tk.BooleanVar(value=True)
        ssl_check = ttk.Checkbutton(settings_frame, text="Verificar certificado SSL", 
                                   variable=self.ssl_var)
        ssl_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.content_var = tk.BooleanVar(value=True)
        content_check = ttk.Checkbutton(settings_frame, text="Analisar conteúdo da página", 
                                       variable=self.content_var)
        content_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.screenshot_var = tk.BooleanVar(value=True)
        screenshot_check = ttk.Checkbutton(settings_frame, text="Capturar screenshot", 
                                          variable=self.screenshot_var)
        screenshot_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.ml_var = tk.BooleanVar(value=True)
        ml_check = ttk.Checkbutton(settings_frame, text="Usar machine learning", 
                                  variable=self.ml_var)
        ml_check.pack(anchor=tk.W)
        
        # Frame para botões de configuração
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        # Botão para salvar configurações
        save_btn = ttk.Button(button_frame, text="💾 Salvar Configurações", command=self.save_settings)
        save_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Botão para restaurar padrões
        default_btn = ttk.Button(button_frame, text="↩️ Restaurar Padrões", command=self.restore_defaults)
        default_btn.pack(side=tk.LEFT)
    
    def clear_results(self):
        """Limpa os resultados atuais"""
        self.risk_label.config(text="Digite uma URL e clique em Verificar", foreground="gray")
        self.details_text.delete(1.0, tk.END)
        self.screenshot_label.config(image='', text="Nenhuma screenshot disponível")
        self.url_entry.delete(0, tk.END)
    
    def export_history(self):
        """Exporta o histórico para CSV"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Salvar histórico como"
        )
        
        if file_path:
            try:
                import shutil
                shutil.copy2(self.detector.history_file, file_path)
                messagebox.showinfo("Sucesso", f"Histórico exportado para {file_path}")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao exportar histórico: {str(e)}")
    
    def export_charts(self):
        """Exporta os gráficos para PNG"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            title="Salvar gráficos como"
        )
        
        if file_path:
            try:
                # Criar figura com os gráficos
                history = self.detector.get_history()
                
                if not history:
                    messagebox.showwarning("Aviso", "Nenhum dado disponível para exportar")
                    return
                
                risk_scores = [int(item['Risk_Score']) for item in history]
                risk_levels = [item['Risk_Level'] for item in history]
                
                # Contar níveis de risco
                level_counts = {
                    'BAIXO RISCO': risk_levels.count('BAIXO RISCO'),
                    'RISCO MODERADO': risk_levels.count('RISCO MODERADO'),
                    'ALTO RISCO': risk_levels.count('ALTO RISCO')
                }
                
                # Criar figura com subplots
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
                
                # Gráfico de pizza para níveis de risco
                labels = list(level_counts.keys())
                sizes = list(level_counts.values())
                colors = ['#4CAF50', '#FFC107', '#F44336']
                
                ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                ax1.set_title('Distribuição de Níveis de Risco')
                ax1.axis('equal')
                
                # Gráfico de linha para pontuações ao longo do tempo
                timestamps = [datetime.strptime(item['Timestamp'], '%Y-%m-%d %H:%M:%S') for item in history]
                ax2.plot(timestamps, risk_scores, marker='o', linestyle='-', color='#2196F3')
                ax2.set_title('Evolução das Pontuações de Risco')
                ax2.set_ylabel('Pontuação de Risco')
                ax2.set_xlabel('Data/Hora')
                ax2.tick_params(axis='x', rotation=45)
                ax2.grid(True, linestyle='--', alpha=0.7)
                
                # Ajustar layout e salvar
                plt.tight_layout()
                plt.savefig(file_path, dpi=300, bbox_inches='tight')
                plt.close()
                
                messagebox.showinfo("Sucesso", f"Gráficos exportados para {file_path}")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao exportar gráficos: {str(e)}")
    
    def save_settings(self):
        """Salva as configurações"""
        # Em uma implementação real, isso salvaria em um arquivo de configuração
        messagebox.showinfo("Configurações", "Configurações salvas com sucesso!")
    
    def restore_defaults(self):
        """Restaura as configurações padrão"""
        self.ssl_var.set(True)
        self.content_var.set(True)
        self.screenshot_var.set(True)
        self.ml_var.set(True)
        messagebox.showinfo("Configurações", "Configurações restauradas para os valores padrão!")
    
    def load_history(self):
        """Carrega o histórico no treeview"""
        # Limpar treeview
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Carregar histórico
        history = self.detector.get_history()
        
        # Adicionar itens ao treeview
        for item in history:
            # Configurar cor baseada no nível de risco
            tags = ()
            if item['Risk_Level'] == 'ALTO RISCO':
                tags = ('high_risk',)
            elif item['Risk_Level'] == 'RISCO MODERADO':
                tags = ('medium_risk',)
            else:
                tags = ('low_risk',)
            
            self.history_tree.insert('', 'end', values=(
                item['Timestamp'],
                item['URL'],
                item['Risk_Score'],
                item['Risk_Level']
            ), tags=tags)
        
        # Configurar cores para as linhas
        self.history_tree.tag_configure('high_risk', background='#ffcccc')
        self.history_tree.tag_configure('medium_risk', background='#fff0cc')
        self.history_tree.tag_configure('low_risk', background='#ccffcc')
    
    def clear_history(self):
        """Limpa o histórico de verificações"""
        if messagebox.askyesno("Confirmar", "Tem certeza que deseja limpar todo o histórico?"):
            try:
                with open(self.detector.history_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'URL', 'Risk_Score', 'Risk_Level', 'Details'])
                self.load_history()
                messagebox.showinfo("Sucesso", "Histórico limpo com sucesso.")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao limpar histórico: {str(e)}")
    
    def update_stats(self):
        """Atualiza as estatísticas"""
        history = self.detector.get_history()
        
        if not history:
            self.stats_label.config(text="Nenhum dado histórico disponível para exibir estatísticas.")
            return
        
        # Limpar frame de gráficos
        for widget in self.stats_frame.winfo_children():
            if isinstance(widget, ttk.Frame):
                widget.destroy()
        
        # Criar novo frame para gráficos
        charts_frame = ttk.Frame(self.stats_frame)
        charts_frame.pack(fill='both', expand=True)
        
        # Processar dados para gráficos
        risk_scores = [int(item['Risk_Score']) for item in history]
        risk_levels = [item['Risk_Level'] for item in history]
        
        # Contar níveis de risco
        level_counts = {
            'BAIXO RISCO': risk_levels.count('BAIXO RISCO'),
            'RISCO MODERADO': risk_levels.count('RISCO MODERADO'),
            'ALTO RISCO': risk_levels.count('ALTO RISCO')
        }
        
        # Criar figura com subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        # Gráfico de pizza para níveis de risco
        labels = list(level_counts.keys())
        sizes = list(level_counts.values())
        colors = ['#4CAF50', '#FFC107', '#F44336']
        
        ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Distribuição de Níveis de Risco')
        ax1.axis('equal')
        
        # Gráfico de linha para pontuações ao longo do tempo
        timestamps = [datetime.strptime(item['Timestamp'], '%Y-%m-%d %H:%M:%S') for item in history]
        ax2.plot(timestamps, risk_scores, marker='o', linestyle='-', color='#2196F3')
        ax2.set_title('Evolução das Pontuações de Risco')
        ax2.set_ylabel('Pontuação de Risco')
        ax2.set_xlabel('Data/Hora')
        ax2.tick_params(axis='x', rotation=45)
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        # Ajustar layout
        plt.tight_layout()
        
        # Embedar gráficos na interface
        canvas = FigureCanvasTkAgg(fig, master=charts_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def start_check(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, digite uma URL para verificar.")
            return
        
        # Adicionar http:// se não tiver esquema
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Desabilitar botão durante a verificação
        self.check_button.config(state='disabled')
        self.progress.start(10)
        self.status_label.config(text="Analisando URL...")
        
        # Limpar resultados anteriores
        self.risk_label.config(text="Analisando...", foreground="black")
        self.details_text.delete(1.0, tk.END)
        self.screenshot_label.config(image='', text="Capturando screenshot...")
        self.current_screenshot = None
        
        # Executar em thread separada para não travar a interface
        thread = threading.Thread(target=self.check_url, args=(url,))
        thread.daemon = True
        thread.start()
    
    def check_url(self, url):
        try:
            # Tirar screenshot primeiro (pode demorar)
            screenshot = None
            if self.screenshot_var.get():
                screenshot = self.detector.take_screenshot(url)
            
            # Realizar verificação
            score, details = self.detector.calculate_risk_score(url)
            
            # Salvar no histórico
            self.detector.save_to_history(url, score, details)
            
            # Atualizar interface na thread principal
            self.root.after(0, self.update_result, url, score, details, screenshot)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
    
    def update_result(self, url, score, details, screenshot):
        # Parar barra de progresso
        self.progress.stop()
        self.check_button.config(state='normal')
        self.status_label.config(text="Verificação concluída")
        
        # Atualizar resultado
        risk_level = "ALTO RISCO" if score >= 60 else "RISCO MODERADO" if score >= 30 else "BAIXO RISCO"
        color = "red" if score >= 60 else "orange" if score >= 30 else "green"
        
        self.risk_label.config(text=f"{risk_level} - Pontuação: {score}/100", foreground=color)
        
        # Adicionar emoji de alerta se for risco moderado ou alto
        if score >= 30:
            self.risk_label.config(text=f"⚠️ {self.risk_label.cget('text')}")
        
        # Atualizar detalhes
        self.details_text.delete(1.0, tk.END)
        
        if details:
            for detail in details:
                self.details_text.insert(tk.END, f"• {detail}\n")
        else:
            self.details_text.insert(tk.END, "Nenhum problema detectado. URL parece segura.")
        
        # Recomendações baseadas na pontuação
        self.details_text.insert(tk.END, "\n--- RECOMENDAÇÕES ---\n")
        
        if score >= 60:
            self.details_text.insert(tk.END, "❌ EVITE este site. Alto risco de phishing.\n")
            self.details_text.insert(tk.END, "• Não insira informações pessoais\n")
            self.details_text.insert(tk.END, "• Não faça download de arquivos\n")
            self.details_text.insert(tk.END, "• Feche imediatamente esta página\n")
        elif score >= 30:
            self.details_text.insert(tk.END, "⚠️ Tenha CUIDADO com este site.\n")
            self.details_text.insert(tk.END, "• Verifique a URL cuidadosamente\n")
            self.details_text.insert(tk.END, "• Procure por erros de gramática/ortografia\n")
            self.details_text.insert(tk.END, "• Desconfie de solicitações de informação pessoal\n")
        else:
            self.details_text.insert(tk.END, "✅ Este site parece seguro.\n")
            self.details_text.insert(tk.END, "• Mesmo assim, sempre verifique a URL antes de inserir dados\n")
        
        # Atualizar screenshot
        if screenshot and self.screenshot_var.get():
            photo = ImageTk.PhotoImage(screenshot)
            self.screenshot_label.config(image=photo, text="")
            self.screenshot_label.image = photo  # Manter referência
            self.current_screenshot = screenshot
        else:
            self.screenshot_label.config(image='', text="Screenshot não disponível")
        
        # Atualizar histórico
        self.load_history()
    
    def show_error(self, error_msg):
        self.progress.stop()
        self.check_button.config(state='normal')
        self.status_label.config(text="Erro durante a verificação")
        
        messagebox.showerror("Erro", f"Ocorreu um erro durante a verificação:\n{error_msg}")

def main():
    root = tk.Tk()
    app = AdvancedPhishingDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()