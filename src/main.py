#!/usr/bin/env python3
"""
Detector de Phishing Avançado
Main application entry point
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.gui import AdvancedPhishingDetectorApp
import tkinter as tk

def main():
    """Main function to start the application"""
    try:
        root = tk.Tk()
        app = AdvancedPhishingDetectorApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Erro ao iniciar a aplicação: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()