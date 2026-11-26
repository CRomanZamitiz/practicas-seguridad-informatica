#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
import html
import json

HOST = "0.0.0.0"
PORT = 8080
MENSAJES = []

HTML_PAGINA = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chat HTTP en Claro - Práctica de Sniffing</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f6fa; color: #1e293b; margin: 0; padding: 20px; }
  .card { max-width: 640px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 16px rgba(0,0,0,.08); overflow: hidden; }
  .header { background: #002b5c; color: #fff; padding: 18px 22px; border-bottom: 4px solid #d4af37; }
  .header h1 { margin: 0; font-size: 1.2rem; }
  .alerta { background: #fef2f2; color: #991b1b; padding: 10px 22px; font-size: 0.9rem; border-bottom: 1px solid #fecaca; }
  .body { padding: 20px 22px; }
  #chat { height: 260px; overflow-y: auto; border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #f8fafc; margin-bottom: 16px; }
  .msg { margin-bottom: 10px; padding: 8px 10px; background: #fff; border-left: 4px solid #0b3d91; border-radius: 4px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
  .meta { font-size: 0.78rem; color: #64748b; margin-bottom: 2px; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
  input { padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.95rem; box-sizing: border-box; }
  #usuario { flex: 1 1 140px; }
  #texto { flex: 2 1 200px; }
  button { flex: 1 1 auto; background: #002b5c; color: #fff; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; }  button:hover { background: #0b3d91; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1>Chat de Practica (HTTP sin cifrar)</h1>
  </div>
  <div class="alerta">
    ⚠️ <strong>Aviso didactico:</strong> Esta pagina usa HTTP en texto plano. <strong>No escribas contrasenas ni datos personales reales.</strong>
  </div>
  <div class="body">
    <div id="chat"><em>Esperando mensajes...</em></div>
    <form id="form">
      <div class="row">
        <input id="usuario" type="text" placeholder="Tu nombre" required>
        <input id="texto" type="text" placeholder="Escribe un mensaje secreto..." required autocomplete="off">
        <button type="submit">Enviar</button>
      </div>
    </form>
  </div>
</div>

<script>
  const chat = document.getElementById('chat');
  const form = document.getElementById('form');
  const usuarioInput = document.getElementById('usuario');
  const textoInput = document.getElementById('texto');

  async function cargarMensajes() {
    try {
      const res = await fetch('/mensajes');
      const data = await res.json();
      if (!data.length) return;
      chat.innerHTML = data.map(m =>
        `<div class="msg"><div class="meta"><strong>${m.usuario}</strong> · ${m.hora}</div><div>${m.texto}</div></div>`
      ).join('');
      chat.scrollTop = chat.scrollHeight;
    } catch (e) {}
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const u = usuarioInput.value.trim();
    const t = textoInput.value.trim();
    if (!u || !t) return;

    // Se envia en texto plano puro para que sea 100% legible en el sniffer
    const payload = `USUARIO=${u} | MENSAJE=${t}`;
    await fetch('/enviar', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: payload
    });
    textoInput.value = '';
    cargarMensajes();
  });

  setInterval(cargarMensajes, 2000);
  cargarMensajes();
</script>
</body>
</html>
"""

class ChatHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silencia el log estandar para mantener limpia la terminal
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGINA.encode("utf-8"))
        elif self.path == "/mensajes":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(MENSAJES[-30:]).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/enviar":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            usuario, texto = "Anónimo", raw
            if " | MENSAJE=" in raw and raw.startswith("USUARIO="):
                partes = raw.split(" | MENSAJE=", 1)
                usuario = partes[0].replace("USUARIO=", "", 1)
                texto = partes[1]

            hora = datetime.now().strftime("%H:%M:%S")
            MENSAJES.append({
                "hora": hora,
                "usuario": html.escape(usuario),
                "texto": html.escape(texto)
            })
            print(f"[{hora}] {self.client_address[0]} -> {raw}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), ChatHandler)
    print(f"Servidor de chat HTTP en claro escuchando en http://{HOST}:{PORT}")
    print("Presiona Ctrl+C para detenerlo.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
