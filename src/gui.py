"""
GUI Module for Advanced Phishing Detector
Contains all the graphical user interface components
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from PIL import Image, ImageTk
import threading
import time
import os
import csv
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from src.detector import AdvancedPhishingDetector
from src.utils import take_screenshot, init_webdriver, load_config, save_config

class AdvancedPhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Detector de Phishing Avançado")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        
        self.center_window(1200, 800)
        self.setup_theme()
        
        self.detector = AdvancedPhishingDetector("data")
        self.driver = init_webdriver()
        self.current_screenshot = None
        self.config = load_config()
        
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
        
        try:
            style.theme_use('clam')
        except:
            pass
        
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        style.configure('Title.TLabel', background='#f0f0f0', font=('Arial', 16, 'bold'))
        style.configure('Risk.TLabel', font=('Arial', 14, 'bold'))
        style.configure('TButton', font=('Arial', 10))
        style.configure('Treeview', font=('Arial', 9))
        style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
    
    def create_widgets(self):
        """Cria todos os widgets da interface"""
        style = ttk.Style()
        style.configure('TNotebook', background='white')
        style.configure('TNotebook.Tab', padding=[10, 5], font=('Arial', 10, 'bold'))
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Criar abas
        self.setup_check_tab()
        self.setup_history_tab()
        self.setup_stats_tab()
        self.setup_settings_tab()
    
    def setup_check_tab(self):
        """Configura a aba de verificação"""
        self.check_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.check_frame, text="🔍 Verificação de URL")
        
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
        """Configura a aba de histórico"""
        self.history_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.history_frame, text="📊 Histórico")
        
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
        """Configura a aba de estatísticas"""
        self.stats_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.stats_frame, text="📈 Estatísticas")
        
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
        """Configura a aba de configurações"""
        self.settings_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.settings_frame, text="⚙️ Configurações")
        
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
        self.ssl_var = tk.BooleanVar(value=self.config.get('check_ssl', True))
        ssl_check = ttk.Checkbutton(settings_frame, text="Verificar certificado SSL", 
                                   variable=self.ssl_var)
        ssl_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.content_var = tk.BooleanVar(value=self.config.get('check_content', True))
        content_check = ttk.Checkbutton(settings_frame, text="Analisar conteúdo da página", 
                                       variable=self.content_var)
        content_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.screenshot_var = tk.BooleanVar(value=self.config.get('take_screenshots', True))
        screenshot_check = ttk.Checkbutton(settings_frame, text="Capturar screenshot", 
                                          variable=self.screenshot_var)
        screenshot_check.pack(anchor=tk.W, pady=(0, 5))
        
        self.ml_var = tk.BooleanVar(value=self.config.get('use_ml', True))
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
        try:
            config = {
                "check_ssl": self.ssl_var.get(),
                "check_content": self.content_var.get(),
                "take_screenshots": self.screenshot_var.get(),
                "use_ml": self.ml_var.get(),
                "timeout": 15
            }
            save_config(config)
            self.config = config
            messagebox.showinfo("Configurações", "Configurações salvas com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar configurações: {str(e)}")
    
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
            if self.config.get('take_screenshots', True):
                screenshot = take_screenshot(self.driver, url, "screenshots")
            
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
        if screenshot and self.config.get('take_screenshots', True):
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