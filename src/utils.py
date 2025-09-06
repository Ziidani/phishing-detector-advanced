"""
Utility functions for the Phishing Detector
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from PIL import Image
import time
import os
import uuid
import json

def init_webdriver():
    """Inicializa o WebDriver para captura de screenshots"""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1200,800")
        return webdriver.Chrome(options=chrome_options)
    except Exception as e:
        print(f"Erro ao inicializar WebDriver: {e}")
        return None

def take_screenshot(driver, url, screenshot_dir="screenshots"):
    """Tira uma screenshot da página web"""
    if not driver:
        return None
        
    try:
        driver.get(url)
        time.sleep(2)
        
        # Tentar fechar popups
        try:
            popups = driver.find_elements(By.XPATH, "//button[contains(text(), 'Aceitar') or contains(text(), 'Fechar') or contains(text(), 'X')]")
            for popup in popups[:2]:
                try:
                    popup.click()
                    time.sleep(0.5)
                except:
                    pass
        except:
            pass
        
        # Tirar screenshot
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)
            
        screenshot_path = os.path.join(screenshot_dir, f"{uuid.uuid4().hex}.png")
        driver.save_screenshot(screenshot_path)
        
        # Redimensionar imagem
        img = Image.open(screenshot_path)
        img.thumbnail((400, 300))
        return img
    except Exception as e:
        print(f"Erro ao tirar screenshot: {e}")
        return None

def ensure_directory(directory):
    """Garante que um diretório existe"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def load_config(config_file="data/config.json"):
    """Carrega configurações do arquivo JSON"""
    default_config = {
        "check_ssl": True,
        "check_content": True,
        "take_screenshots": True,
        "use_ml": True,
        "timeout": 15
    }
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return {**default_config, **json.load(f)}
        except:
            return default_config
    return default_config

def save_config(config, config_file="data/config.json"):
    """Salva configurações no arquivo JSON"""
    ensure_directory(os.path.dirname(config_file))
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)