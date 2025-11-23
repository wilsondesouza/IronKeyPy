import customtkinter as ctk
from tkinter import messagebox, filedialog
import pyperclip
from services.password_generator import PasswordGenerator
from database.database import PasswordDatabase
from services.crypto_manager import CryptoManager
from api.pwned_checker import PwnedChecker
import time
import threading
from PIL import Image
import os
from pathlib import Path

# Retorna o diretório de dados da aplicação no AppData do usuário
def get_app_data_dir():
    
    if os.name == 'nt':  # Windows
        app_data = os.environ.get('APPDATA')
        if not app_data:
            app_data = os.path.expanduser('~\\AppData\\Roaming')
    else:  # Linux/Mac
        app_data = os.path.expanduser('~/.config')
    
    app_dir = os.path.join(app_data, 'IronKeyPy')
    
    # Criar diretório se não existir
    if not os.path.exists(app_dir):
        os.makedirs(app_dir)
    
    return app_dir

# Retorna o caminho completo do config.json e do banco de dados
def get_config_path():
    return os.path.join(get_app_data_dir(), 'config.json')
def get_database_path():
    return os.path.join(get_app_data_dir(), 'ironkeypy.db')

# Exibe tela para configurar ou verificar senha mestre
class MasterPasswordDialog(ctk.CTk):

    def __init__(self, is_setup=False):
        
        super().__init__()
        self.result = None
        self.is_setup = is_setup
        
        # Configuração da janela
        self.wm_iconbitmap("assets/images/icon.ico") # Mudar para caminho absoluto caso queira alterar o ícone
        self.title("Senha Mestre - IronKey Py")
        self.geometry("600x500")
        
        # Centralizar
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.winfo_screenheight() // 2) - (500 // 2)
        self.geometry(f"600x500+{x}+{y}")
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.create_widgets()
    
    def create_widgets(self):
        
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(padx=30, pady=30, fill="both", expand=True)
        
        # Ícone e título
        try:
            logo_image = ctk.CTkImage(
                light_image=Image.open("assets/images/icon.png"), # Mudar para caminho absoluto caso queira alterar o ícone
                dark_image=Image.open("assets/images/icon.png"), # Mudar para caminho absoluto caso queira alterar o ícone
                size=(80, 80)
            )
            icon_label = ctk.CTkLabel(main_frame, image=logo_image, text="")
            icon_label.pack(pady=20)
        except Exception as e:
            # Fallback para emoji se a imagem não for encontrada
            print(f"Aviso: Não foi possível carregar o logo: {e}")
            icon_label = ctk.CTkLabel(main_frame, text="🔒", font=ctk.CTkFont(size=60))
            icon_label.pack(pady=20)
        
        if self.is_setup:
            title_text = "Configure sua Senha Mestre"
            subtitle_text = "Esta senha será usada para criptografar\ntodas as suas senhas salvas."
        else:
            title_text = "Digite sua Senha Mestre"
            subtitle_text = "Desbloqueie o acesso às suas senhas."
        
        title_label = ctk.CTkLabel(main_frame, text=title_text, 
                                   font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        subtitle_label = ctk.CTkLabel(main_frame, text=subtitle_text, 
                                     font=ctk.CTkFont(size=12), text_color="gray")
        subtitle_label.pack(pady=5)
        
        # Campo de senha
        ctk.CTkLabel(main_frame, text="Senha Mestre:", font=ctk.CTkFont(size=14)).pack(pady=(20, 5))
        self.password_entry = ctk.CTkEntry(main_frame, width=350, height=40, show="*",
                                          font=ctk.CTkFont(size=14))
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<Return>", lambda e: self.on_confirm())
        
        # Se for setup, pedir confirmação
        if self.is_setup:
            self.geometry("600x550")
            ctk.CTkLabel(main_frame, text="Confirme a Senha:", font=ctk.CTkFont(size=14)).pack(pady=(10, 5))
            self.confirm_entry = ctk.CTkEntry(main_frame, width=350, height=40, show="*",
                                             font=ctk.CTkFont(size=14))
            self.confirm_entry.pack(pady=5)
            self.confirm_entry.bind("<Return>", lambda e: self.on_confirm())
        
        # Botões
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=30)
        
        confirm_btn = ctk.CTkButton(button_frame, text="Confirmar", 
                                    command=self.on_confirm, width=150, height=40,
                                    font=ctk.CTkFont(size=14, weight="bold"))
        confirm_btn.pack(side="left", padx=10)
        
        if not self.is_setup:
            cancel_btn = ctk.CTkButton(button_frame, text="Sair", 
                                      command=self.on_cancel, width=150, height=40,
                                      fg_color="gray", hover_color="darkgray")
            cancel_btn.pack(side="left", padx=10)
        
        self.password_entry.focus()
    
    def on_confirm(self):
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Aviso", "Digite uma senha!")
            return
        
        if self.is_setup:
            confirm = self.confirm_entry.get()
            if password != confirm:
                messagebox.showerror("Erro", "As senhas não coincidem!")
                self.confirm_entry.delete(0, "end")
                return
            
            if len(password) < 6:
                messagebox.showwarning("Aviso", "A senha deve ter no mínimo 6 caracteres!")
                return
        
        self.result = password
        self.destroy()
    
    def on_cancel(self):
        
        if not self.is_setup:
            messagebox.showinfo("Encerrado", "Aplicação encerrada. Até logo!")
        self.result = None
        self.destroy()


class IronKeyPy(ctk.CTk):
    
    def __init__(self, master_password):
        super().__init__()
        
        # Configuração da janela
        self.wm_iconbitmap("assets/images/icon.ico") # Mudar para caminho absoluto caso queira alterar o ícone
        self.title("IronKey Py - Gerenciador de Senhas")
        self.geometry("1200x800")
        
        # Centralizar
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.winfo_screenheight() // 2) - (800 // 2)
        self.geometry(f"1200x800+{x}+{y}")
         
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.crypto_manager = CryptoManager(config_file=get_config_path())
        
        # Inicializar componentes
        self.password_generator = PasswordGenerator()
        self.database = PasswordDatabase(db_name=get_database_path())
        self.database.set_crypto_manager(self.crypto_manager)
        self.pwned_checker = PwnedChecker()
        
        # Controle de auto-lock
        self.is_locked = False
        self.last_activity = time.time()
        self.auto_lock_timeout = 300  # 5 minutos em segundos
        # Clipboard timer
        self.clipboard_timer = None
        
        self.create_widgets()
        
        # Iniciar monitoramento de atividade
        self.bind_all("<Button>", self.reset_activity_timer)
        self.bind_all("<Key>", self.reset_activity_timer)
        self.check_auto_lock()
        
        self.crypto_manager.initialize(master_password)
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def authenticate(self):
        
        if self.crypto_manager.is_initialized():
            # Login
            dialog = MasterPasswordDialog(self, is_setup=False)
            self.wait_window(dialog)
            
            if dialog.result:
                if self.crypto_manager.verify_master_password(dialog.result):
                    self.crypto_manager.initialize(dialog.result)
                    return True
                else:
                    messagebox.showerror("Erro", "Senha incorreta!")
                    return False
            return False
        else:
            # Primeira configuração
            dialog = MasterPasswordDialog(self, is_setup=True)
            self.wait_window(dialog)
            
            if dialog.result:
                self.crypto_manager.set_master_password(dialog.result)
                self.crypto_manager.initialize(dialog.result)
                messagebox.showinfo("Sucesso", "Senha mestre configurada com sucesso!")
                return True
            return False
    
    def on_closing(self):
        messagebox.showinfo("Encerrado", "Aplicação encerrada. Até logo!")
        self.quit()
    
    def reset_activity_timer(self, event=None):
        self.last_activity = time.time()
    
    def check_auto_lock(self):
        if not self.is_locked:
            elapsed = time.time() - self.last_activity
            if elapsed >= self.auto_lock_timeout:
                self.lock_application()
        
        self.after(10000, self.check_auto_lock)
    
    def lock_application(self):
        
        self.is_locked = True
        self.withdraw()
        
        # Criar janela de desbloqueio como Toplevel para manter o root ativo
        unlock_window = ctk.CTkToplevel(self)
        unlock_window.wm_iconbitmap("assets/images/icon.ico") # Mudar para caminho absoluto caso queira alterar o ícone
        unlock_window.title("Senha Mestre - IronKey Py")
        unlock_window.geometry("600x500")
        unlock_window.transient(self)
        unlock_window.grab_set()
        
        # Centralizar
        unlock_window.update_idletasks()
        x = (unlock_window.winfo_screenwidth() // 2) - (600 // 2)
        y = (unlock_window.winfo_screenheight() // 2) - (500 // 2)
        unlock_window.geometry(f"600x500+{x}+{y}")
        
        result = [None]
        
        def on_confirm():
            password = password_entry.get()
            if not password:
                messagebox.showwarning("Aviso", "Digite uma senha!")
                return
            
            if self.crypto_manager.verify_master_password(password):
                result[0] = password
                unlock_window.destroy()
            else:
                messagebox.showerror("Erro", "Senha incorreta! Tente novamente ou clique em Sair para encerrar.")
                password_entry.delete(0, "end")
        
        def on_cancel():
            result[0] = None
            unlock_window.destroy()
        
        unlock_window.protocol("WM_DELETE_WINDOW", on_cancel)
        
        # Criar interface
        main_frame = ctk.CTkFrame(unlock_window)
        main_frame.pack(padx=30, pady=30, fill="both", expand=True)
        
        # Ícone e título
        try:
            logo_image = ctk.CTkImage(
                light_image=Image.open("assets/images/icon.png"), # Mudar para caminho absoluto caso queira alterar o ícone
                dark_image=Image.open("assets/images/icon.png"), # Mudar para caminho absoluto caso queira alterar o ícone
                size=(80, 80)
            )
            icon_label = ctk.CTkLabel(main_frame, image=logo_image, text="")
            icon_label.pack(pady=20)
        except Exception as e:
            print(f"Aviso: Não foi possível carregar o logo: {e}")
            icon_label = ctk.CTkLabel(main_frame, text="🔒", font=ctk.CTkFont(size=60))
            icon_label.pack(pady=20)
        
        title_label = ctk.CTkLabel(main_frame, text="Digite sua Senha Mestre", 
                                   font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        subtitle_label = ctk.CTkLabel(main_frame, text="Desbloqueie o acesso às suas senhas.", 
                                     font=ctk.CTkFont(size=12), text_color="gray")
        subtitle_label.pack(pady=5)
        
        # Campo de senha
        ctk.CTkLabel(main_frame, text="Senha Mestre:", font=ctk.CTkFont(size=14)).pack(pady=(20, 5))
        password_entry = ctk.CTkEntry(main_frame, width=350, height=40, show="*",
                                      font=ctk.CTkFont(size=14))
        password_entry.pack(pady=5)
        password_entry.bind("<Return>", lambda e: on_confirm())
        
        # Botões
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=30)
        
        confirm_btn = ctk.CTkButton(button_frame, text="Confirmar", 
                                    command=on_confirm, width=150, height=40,
                                    font=ctk.CTkFont(size=14, weight="bold"))
        confirm_btn.pack(side="left", padx=10)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Sair", 
                                  command=on_cancel, width=150, height=40,
                                  fg_color="gray", hover_color="darkgray")
        cancel_btn.pack(side="left", padx=10)
        
        password_entry.focus()
        
        # Aguardar fechamento da janela
        self.wait_window(unlock_window)
        
        if result[0]:
            self.is_locked = False
            self.last_activity = time.time()
            self.deiconify()
        else:
            messagebox.showinfo("Encerrado", "Aplicação encerrada. Até logo!")
            self.quit()
    
    # Copia texto e limpa automaticamente após 30 segundos
    def copy_to_clipboard_with_timer(self, text: str):
        
        pyperclip.copy(text)
        
        # Cancelar timer anterior se existir
        if self.clipboard_timer:
            self.after_cancel(self.clipboard_timer)
        
        # Criar novo timer
        self.clipboard_timer = self.after(30000, self.clear_clipboard)
        
        messagebox.showinfo("Sucesso", "Senha copiada!\nSerá limpa automaticamente em 30 segundos.")
    
    def clear_clipboard(self):
        pyperclip.copy("")
        self.clipboard_timer = None
        
        self.create_widgets()
    
    def create_widgets(self):
        
        # TabView para separar funcionalidades
        self.tabview = ctk.CTkTabview(self, width=780, height=580)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Adicionar abas
        self.tabview.add("Gerar Senha")
        self.tabview.add("Gerenciar Senhas")
        
        # Configurar aba de geração
        self.setup_generator_tab()
        
        # Configurar aba de gerenciamento
        self.setup_manager_tab()
    
    # Configura a aba de geração de senhas
    def setup_generator_tab(self):
        
        tab = self.tabview.tab("Gerar Senha")
        
        # Frame principal
        main_frame = ctk.CTkFrame(tab)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Título
        title_label = ctk.CTkLabel(main_frame, text="Gerador de Senhas Fortes", 
                                   font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(20, 10))
        
        # Frame para informações da senha (Site e Usuário)
        info_frame = ctk.CTkFrame(main_frame)
        info_frame.pack(pady=10, fill="x", padx=40)
        
        ctk.CTkLabel(info_frame, text="Site/Aplicativo:", 
                    font=ctk.CTkFont(size=13)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.site_entry = ctk.CTkEntry(info_frame, width=300, placeholder_text="Ex: Google, Facebook...")
        self.site_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ctk.CTkLabel(info_frame, text="Nome de Usuário:", 
                    font=ctk.CTkFont(size=13)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.username_entry = ctk.CTkEntry(info_frame, width=300, placeholder_text="Ex: usuario@email.com")
        self.username_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # Comprimento da senha
        length_frame = ctk.CTkFrame(main_frame)
        length_frame.pack(pady=10, fill="x", padx=40)
        
        ctk.CTkLabel(length_frame, text="Comprimento:", 
                    font=ctk.CTkFont(size=14)).pack(side="left", padx=10)
        
        self.length_var = ctk.IntVar(value=16)
        self.length_slider = ctk.CTkSlider(length_frame, from_=4, to=32, 
                                          variable=self.length_var, 
                                          number_of_steps=28, width=300)
        self.length_slider.pack(side="left", padx=10)
        
        self.length_label = ctk.CTkLabel(length_frame, text="16", 
                                        font=ctk.CTkFont(size=14, weight="bold"))
        self.length_label.pack(side="left", padx=10)
        
        self.length_var.trace_add("write", self.update_length_label)
        
        # Opções de caracteres
        options_frame = ctk.CTkFrame(main_frame)
        options_frame.pack(pady=20, fill="x", padx=40)
        
        self.lowercase_var = ctk.BooleanVar(value=True)
        self.uppercase_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.symbols_var = ctk.BooleanVar(value=True)
        
        ctk.CTkCheckBox(options_frame, text="Letras Minúsculas (a-z)", 
                       variable=self.lowercase_var).pack(anchor="w", pady=5, padx=20)
        ctk.CTkCheckBox(options_frame, text="Letras Maiúsculas (A-Z)", 
                       variable=self.uppercase_var).pack(anchor="w", pady=5, padx=20)
        ctk.CTkCheckBox(options_frame, text="Números (0-9)", 
                       variable=self.digits_var).pack(anchor="w", pady=5, padx=20)
        ctk.CTkCheckBox(options_frame, text="Símbolos (!@#$%...)", 
                       variable=self.symbols_var).pack(anchor="w", pady=5, padx=20)
        
        # Botão gerar
        generate_btn = ctk.CTkButton(main_frame, text="Gerar Senha", 
                                     command=self.generate_password,
                                     font=ctk.CTkFont(size=16, weight="bold"),
                                     height=40, width=200)
        generate_btn.pack(pady=20)
        
        # Campo de senha gerada
        self.password_entry = ctk.CTkEntry(main_frame, width=500, height=50,
                                          font=ctk.CTkFont(size=18),
                                          justify="center")
        self.password_entry.pack(pady=10)
        
        # Força da senha
        self.strength_label = ctk.CTkLabel(main_frame, text="", 
                                          font=ctk.CTkFont(size=14))
        self.strength_label.pack(pady=5)
        
        # Botões de ação
        action_frame = ctk.CTkFrame(main_frame)
        action_frame.pack(pady=20)
        
        copy_btn = ctk.CTkButton(action_frame, text="📋 Copiar", 
                                command=self.copy_password, width=120)
        copy_btn.pack(side="left", padx=5)
        
        check_btn = ctk.CTkButton(action_frame, text="🔍 Verificar Segurança", 
                                 command=self.check_password_security, width=160,
                                 fg_color="black", hover_color="darkorange")
        check_btn.pack(side="left", padx=5)
        
        save_btn = ctk.CTkButton(action_frame, text="💾 Gerar e Salvar", 
                                command=self.generate_and_save, width=150,
                                fg_color="green", hover_color="darkgreen")
        save_btn.pack(side="left", padx=5)

    # Configura a aba de gerenciamento de senhas
    def setup_manager_tab(self):
    
        tab = self.tabview.tab("Gerenciar Senhas")
        
        # Frame principal
        main_frame = ctk.CTkFrame(tab)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Título e busca
        header_frame = ctk.CTkFrame(main_frame)
        header_frame.pack(pady=10, fill="x", padx=20)
        
        ctk.CTkLabel(header_frame, text="Senhas Salvas", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=10)
        
        self.search_entry = ctk.CTkEntry(header_frame, placeholder_text="Buscar...", width=200)
        self.search_entry.pack(side="right", padx=10)
        self.search_entry.bind("<KeyRelease>", lambda e: self.load_passwords())
        
        # Frame de lista
        list_frame = ctk.CTkFrame(main_frame)
        list_frame.pack(pady=10, fill="both", expand=True, padx=20)
        
        # Scrollable frame para senhas
        self.passwords_frame = ctk.CTkScrollableFrame(list_frame, width=700, height=400)
        self.passwords_frame.pack(fill="both", expand=True)
        
        # Frame de botões
        buttons_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        buttons_frame.pack(pady=10)
        
        refresh_btn = ctk.CTkButton(buttons_frame, text="🔄 Atualizar Lista", 
                                    command=self.load_passwords, width=150)
        refresh_btn.pack(side="left", padx=5)
        
        export_btn = ctk.CTkButton(buttons_frame, text="💾 Exportar Backup", 
                                   command=self.export_backup, width=150,
                                   fg_color="green", hover_color="darkgreen")
        export_btn.pack(side="left", padx=5)
        
        import_btn = ctk.CTkButton(buttons_frame, text="📥 Importar Backup", 
                                   command=self.import_backup, width=150,
                                   fg_color="black", hover_color="darkorange")
        import_btn.pack(side="left", padx=5)
        
        lock_btn = ctk.CTkButton(buttons_frame, text="🔒 Bloquear", 
                                command=self.lock_application, width=120,
                                fg_color="red", hover_color="darkred")
        lock_btn.pack(side="left", padx=5)
        
        info_btn = ctk.CTkButton(buttons_frame, text="ℹ️ Ajuda", 
                                command=self.show_info_menu, width=120,
                                fg_color="purple", hover_color="darkviolet")
        info_btn.pack(side="left", padx=5)
        
        # Carregar senhas
        self.load_passwords()
    
    def update_length_label(self, *args):

        self.length_label.configure(text=str(self.length_var.get()))
    
    def generate_password(self):
        
        # Gera uma senha baseada nas opções selecionadas
        length = self.length_var.get()
        password = self.password_generator.generate_password(
            length=length,
            use_lowercase=self.lowercase_var.get(),
            use_uppercase=self.uppercase_var.get(),
            use_digits=self.digits_var.get(),
            use_symbols=self.symbols_var.get()
        )
        
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        
        # Calcular e exibir força
        strength, score = self.password_generator.calculate_strength(password)
        color = self.get_strength_color(score)
        self.strength_label.configure(text=f"Força: {strength} ({score}%)", text_color=color)
    
    def get_strength_color(self, score):

        if score >= 80:
            return "green"
        elif score >= 60:
            return "lightgreen"
        elif score >= 40:
            return "yellow"
        elif score >= 20:
            return "orange"
        else:
            return "red"
    
    def copy_password(self):

        password = self.password_entry.get()
        if password:
            self.copy_to_clipboard_with_timer(password)
        else:
            messagebox.showwarning("Aviso", "Nenhuma senha para copiar!")
    
    def generate_and_save(self):

        # Validar campos obrigatórios
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        
        if not site:
            messagebox.showwarning("Aviso", "Por favor, preencha o campo Site/Aplicativo!")
            self.site_entry.focus()
            return
        
        if not username:
            messagebox.showwarning("Aviso", "Por favor, preencha o campo Nome de Usuário!")
            self.username_entry.focus()
            return
        
        # Gerar a senha
        length = self.length_var.get()
        password = self.password_generator.generate_password(
            length=length,
            use_lowercase=self.lowercase_var.get(),
            use_uppercase=self.uppercase_var.get(),
            use_digits=self.digits_var.get(),
            use_symbols=self.symbols_var.get()
        )
        
        # Exibir a senha gerada
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        
        # Calcular e exibir força
        strength, score = self.password_generator.calculate_strength(password)
        color = self.get_strength_color(score)
        self.strength_label.configure(text=f"Força: {strength} ({score}%)", text_color=color)
        
        # Salvar no banco de dados
        if self.database.add_password(site, username, password):
            messagebox.showinfo("Sucesso", f"Senha gerada e salva com sucesso!\n\nSite: {site}\nUsuário: {username}")
            
            # Limpar campos após salvar
            self.site_entry.delete(0, "end")
            self.username_entry.delete(0, "end")
            
            self.load_passwords()
            
            # Copiar senha automaticamente com timer
            self.copy_to_clipboard_with_timer(password)
        else:
            messagebox.showerror("Erro", "Falha ao salvar senha no banco de dados!")
    
    # Exibe diálogo para salvar a senha (caso senha já tenha sido gerada)
    def show_save_dialog(self):
        
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Aviso", "Gere uma senha primeiro!")
            return
        
        # Criar janela de diálogo
        dialog = ctk.CTkToplevel(self)
        dialog.title("Salvar Senha")
        dialog.geometry("400x300")
        dialog.transient(self)
        dialog.grab_set()
        
        # Centralizar diálogo
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (300 // 2)
        dialog.geometry(f"400x300+{x}+{y}")
        
        frame = ctk.CTkFrame(dialog)
        frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        ctk.CTkLabel(frame, text="Informações da Senha", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        ctk.CTkLabel(frame, text="Site/Aplicativo:").pack(pady=5)
        site_entry = ctk.CTkEntry(frame, width=300)
        site_entry.pack(pady=5)
        
        ctk.CTkLabel(frame, text="Nome de Usuário:").pack(pady=5)
        username_entry = ctk.CTkEntry(frame, width=300)
        username_entry.pack(pady=5)
        
        # Função para salvar a senha
        def save():
            site = site_entry.get().strip()
            username = username_entry.get().strip()
            
            if not site or not username:
                messagebox.showwarning("Aviso", "Preencha todos os campos!")
                return
            
            if self.database.add_password(site, username, password):
                messagebox.showinfo("Sucesso", "Senha salva com sucesso!")
                dialog.destroy()
                self.load_passwords()
            else:
                messagebox.showerror("Erro", "Falha ao salvar senha!")
        
        ctk.CTkButton(frame, text="Salvar", command=save, width=150).pack(pady=20)
    
    def load_passwords(self):

        # Limpar frame
        for widget in self.passwords_frame.winfo_children():
            widget.destroy()
        
        # Buscar senhas
        search_term = self.search_entry.get().strip()
        if search_term:
            passwords = self.database.search_passwords(search_term)
        else:
            passwords = self.database.get_all_passwords()
        
        if not passwords:
            ctk.CTkLabel(self.passwords_frame, text="Nenhuma senha salva ainda.", 
                        font=ctk.CTkFont(size=14)).pack(pady=20)
            return
        
        # Exibir senhas
        for pwd_id, site, username, password, created_at in passwords:
            self.create_password_card(pwd_id, site, username, password, created_at)
            
    # Cria um card para cada senha
    def create_password_card(self, pwd_id, site, username, password, created_at):
        
        card = ctk.CTkFrame(self.passwords_frame, fg_color=("#E0E0E0", "#2B2B2B"))
        card.pack(pady=5, padx=10, fill="x")
        
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(info_frame, text=site, 
                    font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Usuário: {username}", 
                    font=ctk.CTkFont(size=12)).pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Senha: {'•' * len(password)}", 
                    font=ctk.CTkFont(size=12)).pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Criada em: {created_at}", 
                    font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w")
        
        buttons_frame = ctk.CTkFrame(card, fg_color="transparent")
        buttons_frame.pack(side="right", padx=10, pady=10)
        
        copy_btn = ctk.CTkButton(buttons_frame, text="📋 Copiar", width=90,
                                command=lambda p=password: self.copy_saved_password(p))
        copy_btn.pack(pady=2)
        
        check_btn = ctk.CTkButton(buttons_frame, text="🔍 Verificar", width=90,
                                 fg_color="black", hover_color="darkorange",
                                 command=lambda p=password, s=site: self.check_saved_password_security(p, s))
        check_btn.pack(pady=2)
        
        delete_btn = ctk.CTkButton(buttons_frame, text="🗑️ Excluir", width=90,
                                  fg_color="red", hover_color="darkred",
                                  command=lambda i=pwd_id: self.delete_password(i))
        delete_btn.pack(pady=2)
    
    def copy_saved_password(self, password):

        self.copy_to_clipboard_with_timer(password)
    
    def delete_password(self, pwd_id):

        if messagebox.askyesno("Confirmar", "Deseja realmente excluir esta senha?"):
            if self.database.delete_password(pwd_id):
                messagebox.showinfo("Sucesso", "Senha excluída!")
                self.load_passwords()
            else:
                messagebox.showerror("Erro", "Falha ao excluir senha!")
    
    def check_password_security(self):

        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Aviso", "Gere uma senha primeiro!")
            return
        
        # Criar diálogo de progresso
        progress_dialog = ctk.CTkToplevel(self)
        progress_dialog.title("Verificando Segurança")
        progress_dialog.geometry("400x150")
        progress_dialog.transient(self)
        progress_dialog.grab_set()
        
        # Centralizar
        progress_dialog.update_idletasks()
        x = (progress_dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (progress_dialog.winfo_screenheight() // 2) - (150 // 2)
        progress_dialog.geometry(f"400x150+{x}+{y}")
        
        label = ctk.CTkLabel(progress_dialog, text="🔍 Verificando senha...\n\nConsultando banco de dados Have I Been Pwned",
                            font=ctk.CTkFont(size=14))
        label.pack(pady=30)
        
        progress = ctk.CTkProgressBar(progress_dialog, width=300)
        progress.pack(pady=10)
        progress.set(0)
        progress.start()
        
        # Função para verificar em thread separada
        def check_in_thread():
            try:
                is_pwned, count = self.pwned_checker.check_password(password)
                advice = self.pwned_checker.get_password_strength_advice(is_pwned, count)
                
                # Atualizar UI na thread principal
                progress_dialog.after(0, lambda: show_result(advice, is_pwned))
                
            except Exception as e:
                progress_dialog.after(0, lambda: show_error(str(e)))
        
        def show_result(advice, is_pwned):
            progress_dialog.destroy()
            
            if is_pwned:
                messagebox.showwarning("⚠️ Senha Comprometida", advice)
            else:
                messagebox.showinfo("✅ Senha Segura", advice)
        
        def show_error(error_msg):
            progress_dialog.destroy()
            messagebox.showerror("Erro", f"Não foi possível verificar a senha:\n\n{error_msg}")
        
        # Executar verificação em thread separada
        thread = threading.Thread(target=check_in_thread, daemon=True)
        thread.start()
    
    # Verifica se uma senha salva está comprometida
    def check_saved_password_security(self, password, site):
        
        def check_in_thread():
            try:
                is_pwned, count = self.pwned_checker.check_password(password)
                advice = self.pwned_checker.get_password_strength_advice(is_pwned, count)
                
                # Mostrar resultado
                self.after(0, lambda: show_result(advice, is_pwned, site))
                
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Erro", f"Não foi possível verificar:\n{str(e)}"))
        
        def show_result(advice, is_pwned, site_name):
            if is_pwned:
                messagebox.showwarning(f"⚠️ Senha de '{site_name}' Comprometida", advice)
            else:
                messagebox.showinfo(f"✅ Senha de '{site_name}' Segura", advice)
        
        # Criar diálogo de progresso
        progress_dialog = ctk.CTkToplevel(self)
        progress_dialog.title("Verificando Segurança")
        progress_dialog.geometry("400x150")
        progress_dialog.transient(self)
        
        # Centralizar
        progress_dialog.update_idletasks()
        x = (progress_dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (progress_dialog.winfo_screenheight() // 2) - (150 // 2)
        progress_dialog.geometry(f"400x150+{x}+{y}")
        
        label = ctk.CTkLabel(progress_dialog, text=f"🔍 Verificando senha de '{site}'...",
                            font=ctk.CTkFont(size=14))
        label.pack(pady=30)
        
        progress = ctk.CTkProgressBar(progress_dialog, width=300)
        progress.pack(pady=10)
        progress.set(0)
        progress.start()
        
        def close_dialog():
            progress_dialog.destroy()

        self.after(100, close_dialog)
        
        # Executar verificação em thread separada
        thread = threading.Thread(target=check_in_thread, daemon=True)
        thread.start()
    
    def export_backup(self):

        # Exporta o banco de dados criptografado
        try:
            file_path = filedialog.asksaveasfilename(
                title="Salvar Backup",
                defaultextension=".db",
                filetypes=[("Database files", "*.db"), ("All files", "*.*")],
                initialfile="ironkeypy_backup.db"
            )
            
            # Salvar o arquivo
            if file_path:
                import shutil
                shutil.copy(self.database.db_name, file_path)
                messagebox.showinfo("Sucesso", f"Backup exportado com sucesso!\n\nLocal: {file_path}\n\nNota: O backup está criptografado com sua senha mestre.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar backup: {e}")
    
    # # Importa um arquivo de backup, substituindo o banco atual
    def import_backup(self):
        
        if messagebox.askyesno("Confirmar", 
                              "ATENÇÃO: Importar um backup substituirá TODAS as senhas atuais!\n\nDeseja continuar?"):
            # Selecionar arquivo de backup
            try:
                file_path = filedialog.askopenfilename(
                    title="Selecionar Backup",
                    filetypes=[("Database files", "*.db"), ("All files", "*.*")]
                )
                
                if file_path:
                    import shutil
                    # Fazer backup do atual antes de substituir
                    shutil.copy(self.database.db_name, f"{self.database.db_name}.old")
                    
                    # Substituir com o backup
                    shutil.copy(file_path, self.database.db_name)
                    
                    # Recarregar senhas
                    self.load_passwords()
                    
                    messagebox.showinfo("Sucesso", "Backup importado com sucesso!\n\nUm backup do banco anterior foi salvo como '.old'")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao importar backup: {e}")
                # Tentar restaurar backup antigo
                try:
                    import shutil
                    shutil.copy(f"{self.database.db_name}.old", self.database.db_name)
                    messagebox.showinfo("Recuperação", "Banco de dados anterior foi restaurado.")
                except:
                    pass
    
    def show_info_menu(self):

        info_window = ctk.CTkToplevel(self)
        info_window.title("Ajuda e Informações - IronKey Py")
        info_window.geometry("600x500")
        info_window.transient(self)
        info_window.grab_set()
        
        # Centralizar
        info_window.update_idletasks()
        x = (info_window.winfo_screenwidth() // 2) - (600 // 2)
        y = (info_window.winfo_screenheight() // 2) - (500 // 2)
        info_window.geometry(f"600x500+{x}+{y}")
        
        main_frame = ctk.CTkFrame(info_window)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Título
        title = ctk.CTkLabel(main_frame, text="ℹ️ Informações da Aplicação",
                            font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=10)
        
        # Informações sobre localização dos arquivos
        info_text = f"""📂 Localização dos Dados:

Os arquivos da aplicação são armazenados em:
{get_app_data_dir()}

Arquivos:
• config.json - Configurações e salt de criptografia
• ironkeypy.db - Banco de dados de senhas (criptografado)

⚠️ IMPORTANTE:
Se você desinstalar o IronKey Py, esses arquivos NÃO serão
automaticamente deletados. Isso garante que seus dados não
sejam perdidos acidentalmente.

Para remover completamente:
1. Exporte um backup das suas senhas
2. Delete a pasta manualmente no local acima
3. Ou use o botão "Limpar Dados" abaixo
        """
        
        info_label = ctk.CTkLabel(main_frame, text=info_text,
                                 font=ctk.CTkFont(size=12),
                                 justify="left")
        info_label.pack(pady=10, padx=10)
        
        # Botões de ação
        buttons_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        buttons_frame.pack(pady=20)
        
        def open_data_folder():
            import subprocess
            subprocess.Popen(f'explorer "{get_app_data_dir()}"')
        
        def clean_all_data():
            """Remove todos os dados da aplicação"""
            if messagebox.askyesno("⚠️ ATENÇÃO", 
                                  "Isso irá deletar PERMANENTEMENTE:\n\n"
                                  "• Todas as senhas salvas\n"
                                  "• Configurações\n"
                                  "• Senha mestre\n\n"
                                  "Esta ação NÃO pode ser desfeita!\n\n"
                                  "Deseja continuar?"):
                
                if messagebox.askyesno("Confirmação Final", 
                                      "Tem certeza ABSOLUTA?\n\n"
                                      "Recomendamos fazer backup antes!"):
                    try:
                        import shutil
                        shutil.rmtree(get_app_data_dir())
                        messagebox.showinfo("Concluído", 
                                          "Todos os dados foram removidos.\n\n"
                                          "A aplicação será encerrada.")
                        info_window.destroy()
                        self.quit()
                    except Exception as e:
                        messagebox.showerror("Erro", f"Falha ao limpar dados: {e}")
        
        open_btn = ctk.CTkButton(buttons_frame, text="📁 Abrir Pasta de Dados",
                                command=open_data_folder, width=200)
        open_btn.pack(pady=5)
        
        clean_btn = ctk.CTkButton(buttons_frame, text="🗑️ Limpar Todos os Dados",
                                 command=clean_all_data, width=200,
                                 fg_color="red", hover_color="darkred")
        clean_btn.pack(pady=5)
        
        close_btn = ctk.CTkButton(buttons_frame, text="Fechar",
                                 command=info_window.destroy, width=200,
                                 fg_color="gray", hover_color="darkgray")
        close_btn.pack(pady=5)


def main():
    
    # Autenticação inicial
    crypto_manager = CryptoManager(config_file=get_config_path())
    if crypto_manager.is_initialized():
        while True:
            dialog = MasterPasswordDialog(is_setup=False)
            dialog.mainloop()
            password = dialog.result
            
            if password and crypto_manager.verify_master_password(password):
                # Abre gerenciador principal
                app = IronKeyPy(password)
                app.mainloop()
                break
            elif password is None:
                # Cancelado
                break
            else:
                messagebox.showerror("Erro", "Senha incorreta! Tente novamente ou clique em Sair para encerrar.")
                
    else:
        dialog = MasterPasswordDialog(is_setup=True)
        dialog.mainloop()
        password = dialog.result
        if password:
            crypto_manager.set_master_password(password)
            # Abre gerenciador principal
            app = IronKeyPy(password)
            app.mainloop()
        else:
            # Cancelado
            return

if __name__ == "__main__":
    main()