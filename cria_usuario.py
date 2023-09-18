import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import os

# Obtenha o diretório atual do script
diretorio_atual = os.path.dirname(os.path.abspath(__file__))

# Chave de criptografia (usando 'teste' e 'admin' como chave para demonstração)
chave = Fernet.generate_key()

# Função para criar uma conta e salvar no arquivo
def criar_conta():
    usuario = entrada_usuario.get()
    email = entrada_email.get()
    senha = entrada_senha.get()

    if not usuario or not email or not senha:
        messagebox.showerror("Erro", "Preencha todos os campos.")
    elif usuario_existe(usuario):
        messagebox.showerror("Erro", "Este usuário já existe.")
    elif email_existe(email):
        messagebox.showerror("Erro", "Este email já está em uso.")
    else:
        # Criptografa os dados usando a chave definida
        dados = f"Usuário: {usuario}, Email: {email}, Senha: {senha}\n"
        dados_criptografados = criptografar_dados(dados)

        with open(os.path.join(diretorio_atual, "users.txt"), "a") as arquivo:
            arquivo.write(dados_criptografados)
        messagebox.showinfo("Sucesso", "Conta criada com sucesso!")

# Função para verificar se o usuário é um administrador
def verificar_admin():
    usuario_admin = entrada_usuario_admin.get()
    senha_admin = entrada_senha_admin.get()

    # Verifique se as credenciais correspondem ao 'teste' e 'admin'
    if usuario_admin == "teste" and senha_admin == "admin":
        with open(os.path.join(diretorio_atual, "users.txt"), "r") as arquivo:
            dados_criptografados = arquivo.readlines()
        
        # Descriptografa e exibe os dados usando a chave definida
        dados_descriptografados = descriptografar_dados(dados_criptografados)
        messagebox.showinfo("Acesso do Administrador", f"Dados dos Usuários:\n{dados_descriptografados}")
    else:
        messagebox.showerror("Erro", "Credenciais do administrador incorretas.")

# Função para verificar se um usuário já existe no arquivo
def usuario_existe(usuario):
    with open(os.path.join(diretorio_atual, "users.txt"), "r") as arquivo:
        dados_criptografados = arquivo.readlines()
    
    # Descriptografa os dados e verifica a existência do usuário
    dados_descriptografados = descriptografar_dados(dados_criptografados)
    return f"Usuário: {usuario}" in dados_descriptografados

# Função para verificar se um email já existe no arquivo
def email_existe(email):
    with open(os.path.join(diretorio_atual, "users.txt"), "r") as arquivo:
        dados_criptografados = arquivo.readlines()
    
    # Descriptografa os dados e verifica a existência do email
    dados_descriptografados = descriptografar_dados(dados_criptografados)
    return f"Email: {email}" in dados_descriptografados

# Função para criptografar dados usando a chave definida
def criptografar_dados(dados):
    cipher_suite = Fernet(chave)
    return cipher_suite.encrypt(dados.encode()).decode()

# Função para descriptografar dados usando a chave definida
def descriptografar_dados(dados_criptografados):
    cipher_suite = Fernet(chave)
    dados_descriptografados = []
    for dado in dados_criptografados:
        dados = cipher_suite.decrypt(dado.encode()).decode()
        dados_descriptografados.append(dados)
    return "\n".join(dados_descriptografados)

# Criar janela principal
janela = tk.Tk()
janela.title("Criação de Conta e Acesso do Administrador")

# Estilo temático 'ttkthemes'
estilo = ttk.Style()
estilo.theme_use("clam")  # Você pode escolher outro tema se preferir

# Rótulos e entradas de texto para criar conta
rotulo_usuario = ttk.Label(janela, text="Usuário:")
rotulo_email = ttk.Label(janela, text="Email:")
rotulo_senha = ttk.Label(janela, text="Senha:")

entrada_usuario = ttk.Entry(janela)
entrada_email = ttk.Entry(janela)
entrada_senha = ttk.Entry(janela, show="*")

botao_criar_conta = ttk.Button(janela, text="Criar Conta", command=criar_conta)

# Rótulo e entrada de usuário e senha para acesso do administrador
rotulo_usuario_admin = ttk.Label(janela, text="Usuário do Administrador:")
entrada_usuario_admin = ttk.Entry(janela)
rotulo_senha_admin = ttk.Label(janela, text="Senha do Administrador:")
entrada_senha_admin = ttk.Entry(janela, show="*")
botao_acesso_admin = ttk.Button(janela, text="Acesso do Administrador", command=verificar_admin)

# Posicionamento dos elementos na janela
rotulo_usuario.grid(row=0, column=0, padx=10, pady=5)
rotulo_email.grid(row=1, column=0, padx=10, pady=5)
rotulo_senha.grid(row=2, column=0, padx=10, pady=5)

entrada_usuario.grid(row=0, column=1, padx=10, pady=5)
entrada_email.grid(row=1, column=1, padx=10, pady=5)
entrada_senha.grid(row=2, column=1, padx=10, pady=5)

botao_criar_conta.grid(row=3, columnspan=2, padx=10, pady=10)

rotulo_usuario_admin.grid(row=4, column=0, padx=10, pady=5)
entrada_usuario_admin.grid(row=4, column=1, padx=10, pady=5)
rotulo_senha_admin.grid(row=5, column=0, padx=10, pady=5)
entrada_senha_admin.grid(row=5, column=1, padx=10, pady=5)
botao_acesso_admin.grid(row=6, columnspan=2, padx=10, pady=10)

janela.mainloop()