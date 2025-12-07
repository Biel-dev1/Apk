
import socket
import threading
import time
import hashlib
import json
import secrets
from datetime import datetime

# ==================== CONFIGURAÇÕES ====================
PORTA = 6666
ADMIN_PASSWORD = "admin123"  # MUDA ISSO!
ADMIN_SALT = "f3a7b2c9d1e4f5a6"  # Salt fixo para PBKDF2 (gere um novo em produção!)
MAX_NICK_LENGTH = 20
MIN_NICK_LENGTH = 2
MAX_MSG_LENGTH = 500
MAX_RECV_SIZE = 1024
RECV_TIMEOUT = 10  # Timeout em segundos para todas as operações de rede
RATE_LIMIT_SECONDS = 1  # Tempo mínimo entre mensagens
MAX_CONEXOES_POR_IP = 3  # Máximo de conexões simultâneas por IP
MAX_TENTATIVAS_ADMIN = 3  # Máximo de tentativas de senha admin por IP
WHITELIST_ENABLED = False  # Ativa whitelist de IPs
WHITELIST_IPS = []  # ["192.168.1.100", "192.168.1.101"]
NICKS_RESERVADOS = {"system", "admin", "servidor", "server", "root", "moderator", "mod"}

# ==================== DADOS GLOBAIS ====================
clientes = {}  # {nick: conn}
ips_clientes = {}  # {nick: ip}
conexoes_por_ip = {}  # {ip: count}
nicks_usados = set()  # Nicks atualmente em uso
admins = set()  # Nicks de admins logados
banidos_ip = {}  # {ip: {"motivo": str, "data": timestamp}}
banidos_nick = {}  # {nick: {"motivo": str, "data": timestamp}}
ultimas_msgs = {}  # {nick: timestamp} - Rate limiting
tentativas_suspeitas = {}  # {ip: count} - Anti-brute force
tentativas_admin = {}  # {ip: count} - Limite de tentativas de login admin
lock = threading.Lock()  # Thread safety

# ==================== FUNÇÕES DE SEGURANÇA ====================

def log(mensagem, tipo="INFO"):
    """Log com timestamp e sanitização"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Sanitiza a mensagem antes de logar para prevenir log injection
    mensagem_safe = sanitizar(str(mensagem))
    print(f"[{timestamp}] [{tipo}] {mensagem_safe}")
    
    # Salva em arquivo
    try:
        with open("chat_server.log", "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{tipo}] {mensagem_safe}\n")
    except Exception as e:
        print(f"[ERRO] Falha ao escrever log: {e}")

def hash_password(senha):
    """Gera hash seguro da senha usando PBKDF2"""
    # PBKDF2 com SHA256, 100.000 iterações
    return hashlib.pbkdf2_hmac(
        'sha256',
        senha.encode('utf-8'),
        ADMIN_SALT.encode('utf-8'),
        100000
    ).hex()

def sanitizar(texto):
    """Remove caracteres perigosos e limita tamanho"""
    if not texto:
        return ""
    # Remove caracteres de controle
    texto = ''.join(c for c in texto if c.isprintable())
    # Remove caracteres perigosos para injection
    caracteres_perigosos = [';', '`', '|', '&', '$', '(', ')', '<', '>', '\n', '\r']
    for char in caracteres_perigosos:
        texto = texto.replace(char, '')
    # Limita tamanho
    return texto[:MAX_MSG_LENGTH]

def safe_recv(conn):
    """Recebe dados de forma segura com validações"""
    try:
        # Recebe no máximo MAX_RECV_SIZE bytes
        data = conn.recv(MAX_RECV_SIZE)
        
        if not data:
            return None
        
        # Decode com tratamento de erros
        msg = data.decode('utf-8', errors='ignore').strip()
        
        # Verifica tamanho máximo
        if len(msg) > MAX_MSG_LENGTH:
            log(f"Payload muito grande recebido ({len(msg)} bytes), conexão fechada", "SECURITY")
            try:
                conn.close()
            except:
                pass
            return None
        
        return msg
    
    except socket.timeout:
        log("Timeout na recepção de dados", "SECURITY")
        try:
            conn.close()
        except:
            pass
        return None
    
    except Exception as e:
        log(f"Erro ao receber dados: {e}", "ERROR")
        try:
            conn.close()
        except:
            pass
        return None

def validar_nick(nick):
    """Valida formato do nick"""
    if not nick:
        return False, "Nick vazio"
    if len(nick) < MIN_NICK_LENGTH:
        return False, f"Nick muito curto (mínimo {MIN_NICK_LENGTH})"
    if len(nick) > MAX_NICK_LENGTH:
        return False, f"Nick muito longo (máximo {MAX_NICK_LENGTH})"
    if not nick.replace("_", "").replace("-", "").isalnum():
        return False, "Nick só pode ter letras, números, _ e -"
    
    # Verifica nicks reservados
    if nick.lower() in NICKS_RESERVADOS:
        return False, "Nick reservado pelo sistema"
    
    return True, "OK"

def verificar_whitelist(ip):
    """Verifica se IP está na whitelist"""
    if not WHITELIST_ENABLED:
        return True
    return ip in WHITELIST_IPS

def verificar_ban_ip(ip):
    """Verifica se IP está banido"""
    return ip in banidos_ip

def verificar_ban_nick(nick):
    """Verifica se nick está banido"""
    return nick.lower() in banidos_nick

def rate_limit(nick):
    """Anti-flood: limita msgs por tempo"""
    agora = time.time()
    with lock:
        if nick in ultimas_msgs:
            if agora - ultimas_msgs[nick] < RATE_LIMIT_SECONDS:
                return False
        ultimas_msgs[nick] = agora
    return True

def registrar_tentativa_suspeita(ip):
    """Registra tentativas suspeitas"""
    with lock:
        if ip not in tentativas_suspeitas:
            tentativas_suspeitas[ip] = 0
        tentativas_suspeitas[ip] += 1
        
        if tentativas_suspeitas[ip] >= 5:
            banir_ip(ip, "SYSTEM", "Múltiplas tentativas suspeitas")
            log(f"IP {ip} auto-banido por tentativas suspeitas", "SECURITY")

def registrar_tentativa_admin(ip):
    """Registra tentativas de login admin e bane após limite"""
    with lock:
        if ip not in tentativas_admin:
            tentativas_admin[ip] = 0
        tentativas_admin[ip] += 1
        
        if tentativas_admin[ip] >= MAX_TENTATIVAS_ADMIN:
            banir_ip(ip, "SYSTEM", f"Excedeu {MAX_TENTATIVAS_ADMIN} tentativas de senha admin")
            log(f"IP {ip} auto-banido por tentativas de brute force em senha admin", "SECURITY")
            return False
        
        return True

def verificar_limite_conexoes(ip):
    """Verifica se IP não excedeu limite de conexões"""
    with lock:
        count = conexoes_por_ip.get(ip, 0)
        if count >= MAX_CONEXOES_POR_IP:
            return False
        conexoes_por_ip[ip] = count + 1
    return True

def liberar_conexao(ip):
    """Libera slot de conexão do IP"""
    with lock:
        if ip in conexoes_por_ip:
            conexoes_por_ip[ip] -= 1
            if conexoes_por_ip[ip] <= 0:
                del conexoes_por_ip[ip]

# ==================== FUNÇÕES DE COMUNICAÇÃO ====================

def broadcast(mensagem, exceto=None):
    """Envia mensagem pra todos menos 'exceto'"""
    with lock:
        clientes_lista = list(clientes.items())
    
    for nick, conn in clientes_lista:
        if nick != exceto:
            enviar(conn, mensagem)

def enviar(conn, msg):
    """Envia mensagem pra um cliente específico com tratamento de erros"""
    try:
        conn.send(f"{msg}\n".encode('utf-8'))
        return True
    except socket.timeout:
        log("Timeout ao enviar mensagem", "WARNING")
        return False
    except Exception as e:
        log(f"Erro ao enviar mensagem: {e}", "ERROR")
        return False

# ==================== COMANDOS ADMINISTRATIVOS ====================

def kickar_usuario(nick_alvo, admin_nick):
    """Kicka um usuário"""
    with lock:
        if nick_alvo not in clientes:
            return False, "Usuário não encontrado"
        
        if nick_alvo in admins:
            return False, "Não pode kickar um admin"
        
        conn = clientes[nick_alvo]
    
    enviar(conn, "[SISTEMA] Você foi kickado do chat!")
    time.sleep(0.5)
    
    try:
        conn.close()
    except:
        pass
    
    broadcast(f"[ADMIN] {nick_alvo} foi kickado por {admin_nick}")
    log(f"{nick_alvo} foi kickado por {admin_nick}", "ADMIN")
    return True, "Usuário kickado"

def banir_nick(nick_alvo, admin_nick, motivo="Sem motivo"):
    """Bane um nick específico"""
    with lock:
        nick_lower = nick_alvo.lower()
        
        if nick_alvo in admins:
            return False, "Não pode banir um admin"
        
        banidos_nick[nick_lower] = {
            "motivo": motivo,
            "data": datetime.now().isoformat(),
            "admin": admin_nick
        }
        
        # Kicka se estiver online
        if nick_alvo in clientes:
            conn = clientes[nick_alvo]
            enviar(conn, f"[SISTEMA] Você foi banido: {motivo}")
            time.sleep(0.5)
            try:
                conn.close()
            except:
                pass
    
    broadcast(f"[ADMIN] {nick_alvo} foi banido por {admin_nick}: {motivo}")
    log(f"{nick_alvo} foi banido por {admin_nick}: {motivo}", "ADMIN")
    salvar_bans()
    return True, "Nick banido"

def banir_ip(ip, admin_nick, motivo="Sem motivo"):
    """Bane um IP"""
    with lock:
        banidos_ip[ip] = {
            "motivo": motivo,
            "data": datetime.now().isoformat(),
            "admin": admin_nick
        }
        
        # Kicka todos com esse IP
        for nick, nick_ip in list(ips_clientes.items()):
            if nick_ip == ip:
                conn = clientes.get(nick)
                if conn:
                    enviar(conn, f"[SISTEMA] Seu IP foi banido: {motivo}")
                    time.sleep(0.5)
                    try:
                        conn.close()
                    except:
                        pass
    
    broadcast(f"[ADMIN] IP {ip} foi banido por {admin_nick}: {motivo}")
    log(f"IP {ip} foi banido por {admin_nick}: {motivo}", "ADMIN")
    salvar_bans()
    return True, "IP banido"

def listar_usuarios():
    """Lista todos online"""
    with lock:
        if not clientes:
            return "Ninguém online"
        
        usuarios = []
        for nick in clientes.keys():
            prefixo = "[ADMIN]" if nick in admins else ""
            usuarios.append(f"{prefixo}{nick}")
        
        return f"Usuários online ({len(usuarios)}): " + ", ".join(usuarios)

def salvar_bans():
    """Salva bans em arquivo"""
    dados = {
        "banidos_ip": banidos_ip,
        "banidos_nick": banidos_nick
    }
    try:
        with open("bans.json", "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log(f"Erro ao salvar bans: {e}", "ERROR")

def carregar_bans():
    """Carrega bans do arquivo"""
    global banidos_ip, banidos_nick
    try:
        with open("bans.json", "r", encoding="utf-8") as f:
            dados = json.load(f)
            banidos_ip = dados.get("banidos_ip", {})
            banidos_nick = dados.get("banidos_nick", {})
            log(f"Carregados {len(banidos_ip)} IPs e {len(banidos_nick)} nicks banidos", "INFO")
    except FileNotFoundError:
        log("Nenhum arquivo de bans encontrado, iniciando limpo", "INFO")
    except Exception as e:
        log(f"Erro ao carregar bans: {e}", "ERROR")

# ==================== HANDLER DE CLIENTE ====================

def handle_cliente(conn, addr):
    """Gerencia cada cliente conectado"""
    nick = None
    is_admin = False
    ip = addr[0]
    
    try:
        # Define timeout para todas as operações de rede
        conn.settimeout(RECV_TIMEOUT)
        
        # === VERIFICAÇÕES INICIAIS ===
        
        # Whitelist
        if not verificar_whitelist(ip):
            enviar(conn, "[ERRO] IP não autorizado")
            log(f"Conexão rejeitada de IP não whitelisted: {ip}", "SECURITY")
            return
        
        # Ban de IP
        if verificar_ban_ip(ip):
            info = banidos_ip[ip]
            enviar(conn, f"[ERRO] IP banido: {info['motivo']}")
            log(f"Tentativa de conexão de IP banido: {ip}", "SECURITY")
            return
        
        # Limite de conexões por IP
        if not verificar_limite_conexoes(ip):
            enviar(conn, "[ERRO] Muitas conexões deste IP")
            log(f"IP {ip} excedeu limite de conexões", "SECURITY")
            registrar_tentativa_suspeita(ip)
            return
        
        # === AUTENTICAÇÃO ===
        
        enviar(conn, "Digite seu nick: ")
        
        nick = safe_recv(conn)
        if nick is None:
            return
        
        nick = sanitizar(nick)
        
        # Valida formato do nick
        valido, erro = validar_nick(nick)
        if not valido:
            enviar(conn, f"[ERRO] {erro}")
            registrar_tentativa_suspeita(ip)
            return
        
        # Verifica se nick já está em uso
        with lock:
            if nick in nicks_usados:
                enviar(conn, "[ERRO] Nick já está em uso!")
                registrar_tentativa_suspeita(ip)
                return
        
        # Verifica ban de nick
        if verificar_ban_nick(nick):
            info = banidos_nick[nick.lower()]
            enviar(conn, f"[ERRO] Nick banido: {info['motivo']}")
            log(f"Tentativa de usar nick banido: {nick} ({ip})", "SECURITY")
            registrar_tentativa_suspeita(ip)
            return
        
        # Pergunta senha de admin (opcional)
        enviar(conn, "Senha admin (enter para pular): ")
        senha = safe_recv(conn)
        
        if senha is None:
            return
        
        if senha:
            if hash_password(senha) == hash_password(ADMIN_PASSWORD):
                is_admin = True
                with lock:
                    admins.add(nick)
                enviar(conn, "[SISTEMA] Logado como ADMIN")
                log(f"{nick} ({ip}) logou como ADMIN", "ADMIN")
            else:
                enviar(conn, "[AVISO] Senha incorreta, continuando como usuário normal")
                # Registra tentativa de senha admin incorreta
                if not registrar_tentativa_admin(ip):
                    enviar(conn, "[ERRO] Muitas tentativas de senha admin. Conexão encerrada.")
                    return
        
        # === REGISTRO DO CLIENTE ===
        
        with lock:
            clientes[nick] = conn
            ips_clientes[nick] = ip
            nicks_usados.add(nick)
        
        # Mensagens de boas-vindas
        prefix = "[ADMIN]" if is_admin else "[USER]"
        broadcast(f"[SISTEMA] {prefix} {nick} entrou no chat!", nick)
        enviar(conn, f"Bem-vindo, {nick}!")
        enviar(conn, f"Usuários online: {len(clientes)}")
        
        comandos = "Comandos: /users /quit"
        if is_admin:
            comandos += " /kick /ban /banip /bans"
        enviar(conn, comandos)
        
        log(f"{nick} ({ip}) conectou" + (" [ADMIN]" if is_admin else ""), "CONNECT")
        
        # === LOOP DE MENSAGENS ===
        
        while True:
            try:
                msg = safe_recv(conn)
                
                if msg is None:
                    break
                
                # === PROCESSAMENTO DE COMANDOS ===
                
                if msg.startswith("/"):
                    partes = msg.split(maxsplit=2)
                    cmd = partes[0].lower()
                    
                    # Comando /quit
                    if cmd == "/quit":
                        enviar(conn, "[SISTEMA] Até logo!")
                        break
                    
                    # Comando /users
                    elif cmd == "/users":
                        enviar(conn, listar_usuarios())
                    
                    # Comando /kick (admin)
                    elif cmd == "/kick":
                        if not is_admin:
                            enviar(conn, "[ERRO] Você não é admin!")
                            continue
                        
                        if len(partes) < 2:
                            enviar(conn, "[ERRO] Uso: /kick <nick>")
                            continue
                        
                        alvo = sanitizar(partes[1].strip())
                        sucesso, msg_resp = kickar_usuario(alvo, nick)
                        enviar(conn, f"[{'OK' if sucesso else 'ERRO'}] {msg_resp}")
                    
                    # Comando /ban (admin)
                    elif cmd == "/ban":
                        if not is_admin:
                            enviar(conn, "[ERRO] Você não é admin!")
                            continue
                        
                        if len(partes) < 2:
                            enviar(conn, "[ERRO] Uso: /ban <nick> [motivo]")
                            continue
                        
                        alvo = sanitizar(partes[1].strip())
                        motivo = sanitizar(partes[2]) if len(partes) > 2 else "Sem motivo"
                        sucesso, msg_resp = banir_nick(alvo, nick, motivo)
                        enviar(conn, f"[{'OK' if sucesso else 'ERRO'}] {msg_resp}")
                    
                    # Comando /banip (admin)
                    elif cmd == "/banip":
                        if not is_admin:
                            enviar(conn, "[ERRO] Você não é admin!")
                            continue
                        
                        if len(partes) < 2:
                            enviar(conn, "[ERRO] Uso: /banip <nick_ou_ip> [motivo]")
                            continue
                        
                        alvo = sanitizar(partes[1].strip())
                        motivo = sanitizar(partes[2]) if len(partes) > 2 else "Sem motivo"
                        
                        # Se for um nick, pega o IP dele
                        if alvo in ips_clientes:
                            ip_alvo = ips_clientes[alvo]
                            sucesso, msg_resp = banir_ip(ip_alvo, nick, motivo)
                        else:
                            # Assume que é um IP direto
                            sucesso, msg_resp = banir_ip(alvo, nick, motivo)
                        
                        enviar(conn, f"[{'OK' if sucesso else 'ERRO'}] {msg_resp}")
                    
                    # Comando /bans (admin)
                    elif cmd == "/bans":
                        if not is_admin:
                            enviar(conn, "[ERRO] Você não é admin!")
                            continue
                        
                        info = f"=== BANS ATIVOS ===\n"
                        info += f"IPs banidos: {len(banidos_ip)}\n"
                        for ip_ban, dados in list(banidos_ip.items())[:10]:
                            info += f"  • {ip_ban}: {dados['motivo']}\n"
                        info += f"Nicks banidos: {len(banidos_nick)}\n"
                        for nick_ban, dados in list(banidos_nick.items())[:10]:
                            info += f"  • {nick_ban}: {dados['motivo']}\n"
                        
                        enviar(conn, info)
                    
                    # Comando desconhecido
                    else:
                        enviar(conn, "[ERRO] Comando desconhecido")
                    
                    continue
                
                # === PROCESSAMENTO DE MENSAGEM NORMAL ===
                
                # Rate limiting
                if not rate_limit(nick):
                    enviar(conn, "[AVISO] Aguarde antes de enviar outra mensagem")
                    continue
                
                # Sanitiza e valida
                msg = sanitizar(msg)
                if not msg:
                    continue
                
                # Envia pra todos
                prefix = "[ADMIN]" if is_admin else ""
                mensagem_final = f"{prefix}[{nick}] {msg}"
                broadcast(mensagem_final, nick)
                log(f"{nick}: {msg}", "MESSAGE")
            
            except Exception as e:
                log(f"Erro no loop de {nick}: {e}", "ERROR")
                break
    
    except Exception as e:
        log(f"Erro na conexão de {ip}: {e}", "ERROR")
    
    finally:
        # === LIMPEZA ===
        
        if nick:
            with lock:
                if nick in clientes:
                    del clientes[nick]
                if nick in ips_clientes:
                    del ips_clientes[nick]
                if nick in admins:
                    admins.remove(nick)
                nicks_usados.discard(nick)
            
            broadcast(f"[SISTEMA] {nick} saiu do chat")
            log(f"{nick} desconectou", "DISCONNECT")
        
        liberar_conexao(ip)
        
        try:
            conn.close()
        except:
            pass

# ==================== SERVIDOR PRINCIPAL ====================

def iniciar_servidor():
    """Inicia o servidor"""
    # Carrega bans salvos
    carregar_bans()
    
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        servidor.bind(("0.0.0.0", PORTA))
        servidor.listen()
        
        log(f"Servidor iniciado na porta {PORTA}", "STARTUP")
        log(f"Senha admin configurada: {'SIM' if ADMIN_PASSWORD != 'admin123' else 'NÃO (use senha padrão)'}", "STARTUP")
        log(f"Hash de senha: PBKDF2-SHA256 com 100.000 iterações", "STARTUP")
        log(f"Timeout de conexão: {RECV_TIMEOUT}s", "STARTUP")
        log(f"Rate limiting: {RATE_LIMIT_SECONDS}s entre mensagens", "STARTUP")
        log(f"Max conexões por IP: {MAX_CONEXOES_POR_IP}", "STARTUP")
        log(f"Max tentativas admin por IP: {MAX_TENTATIVAS_ADMIN}", "STARTUP")
        log(f"Whitelist: {'ATIVADA' if WHITELIST_ENABLED else 'DESATIVADA'}", "STARTUP")
        log("Aguardando conexões...", "STARTUP")
        print()
        
        while True:
            conn, addr = servidor.accept()
            thread = threading.Thread(target=handle_cliente, args=(conn, addr))
            thread.daemon = True
            thread.start()
    
    except KeyboardInterrupt:
        log("Servidor encerrado pelo usuário", "SHUTDOWN")
        salvar_bans()
    except Exception as e:
        log(f"Erro fatal: {e}", "ERROR")
    finally:
        servidor.close()

if __name__ == "__main__":
    print("""
    ════════════════════════════════════════
     Chat Terminal - Servidor
     [Versão Segura com PBKDF2 e Timeouts]
    ════════════════════════════════════════
    """)
    iniciar_servidor()
