"""
Script para criar modelos de ML básicos para o detector de phishing
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os

def create_demo_model():
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
        "http://apple.com",
        "http://paypal-verification.com",
        "http://bankofamerica-update.com",
        "http://instagram.com",
        "http://linkedin.com",
        "http://yahoo.com"
    ]
    
    # Rótulos (0 = seguro, 1 = phishing)
    labels = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0]
    
    # Vetorização
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(urls)
    
    # Treinamento do modelo
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, labels)
    
    # Criar diretório data se não existir
    if not os.path.exists('data'):
        os.makedirs('data')
    
    # Salvar modelo
    joblib.dump(model, 'data/phishing_model.pkl')
    joblib.dump(vectorizer, 'data/vectorizer.pkl')
    
    print("Modelos de ML criados com sucesso!")
    print(f"Modelo salvo em: data/phishing_model.pkl")
    print(f"Vectorizer salvo em: data/vectorizer.pkl")

if __name__ == "__main__":
    create_demo_model()