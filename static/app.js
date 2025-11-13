(() => {
  // ============================================
  // Configuración inicial y detección de modo
  // ============================================
  const mode = location.pathname.startsWith('/safe') ? 'safe' : 'vuln';
  const isSafe = mode === 'safe';
  
  // Actualizar título y badge según el modo
  const modeTitle = document.getElementById('modeTitle');
  const modeBadge = document.getElementById('modeBadge');
  const modeInfo = document.getElementById('modeInfo');
  
  if (isSafe) {
    modeTitle.textContent = '✅ Versión SEGURA';
    modeBadge.textContent = '🛡️ MODO PROTEGIDO';
    modeBadge.style.background = 'linear-gradient(135deg, rgba(61, 220, 151, 0.2), rgba(61, 220, 151, 0.1))';
    modeBadge.style.border = '2px solid rgba(61, 220, 151, 0.4)';
    modeBadge.style.color = '#3ddc97';
    modeInfo.querySelector('.info-content').innerHTML = `
      <strong>Modo Seguro:</strong> Estás explorando implementaciones que siguen las mejores prácticas 
      de seguridad según OWASP. Intenta los mismos ataques que en la versión vulnerable y observa cómo 
      son mitigados.
    `;
  } else {
    modeTitle.textContent = '⚠️ Versión VULNERABLE';
    modeBadge.textContent = '🚨 MODO INSEGURO';
    modeBadge.style.background = 'linear-gradient(135deg, rgba(255, 107, 107, 0.2), rgba(255, 107, 107, 0.1))';
    modeBadge.style.border = '2px solid rgba(255, 107, 107, 0.4)';
    modeBadge.style.color = '#ff6b6b';
    modeInfo.querySelector('.info-content').innerHTML = `
      <strong>Modo Vulnerable:</strong> Esta versión contiene vulnerabilidades intencionadas. 
      Explora cada módulo, intenta explotar las debilidades y aprende cómo funcionan los ataques reales.
    `;
  }

  // Actualizar navegación activa
  document.getElementById(isSafe ? 'navSafe' : 'navVuln').style.opacity = '1';
  document.getElementById(isSafe ? 'navVuln' : 'navSafe').style.opacity = '0.6';

  // ============================================
  // Estado de sesión
  // ============================================
  function updateStatus() {
    const status = document.getElementById('status');
    const sessionInfo = document.getElementById('sessionInfo');
    const cookie = document.cookie;
    
    status.textContent = `🔧 Modo activo: ${mode.toUpperCase()}\n🍪 Cookie: ${cookie || '(sin sesión)'}`;
    
    if (cookie) {
      sessionInfo.innerHTML = `
        <strong>✓ Sesión activa</strong><br>
        ${isSafe ? '🔒 Cookie segura (HttpOnly, Secure, SameSite=Strict)' : '⚠️ Cookie insegura (accesible por JavaScript)'}
      `;
      sessionInfo.style.display = 'block';
    } else {
      sessionInfo.innerHTML = `<strong>ℹ️ Sin sesión</strong> - Inicia sesión para probar funcionalidades autenticadas`;
      sessionInfo.style.display = 'block';
      sessionInfo.style.background = 'rgba(255, 204, 77, 0.1)';
      sessionInfo.style.borderColor = 'rgba(255, 204, 77, 0.3)';
      sessionInfo.style.color = '#ffcc4d';
    }
  }
  
  updateStatus();

  // ============================================
  // Funciones auxiliares
  // ============================================
  function showResult(elementId, message, type = 'info') {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    const colors = {
      success: { bg: 'rgba(61, 220, 151, 0.15)', border: 'rgba(61, 220, 151, 0.4)', color: '#3ddc97' },
      error: { bg: 'rgba(255, 107, 107, 0.15)', border: 'rgba(255, 107, 107, 0.4)', color: '#ff6b6b' },
      warning: { bg: 'rgba(255, 204, 77, 0.15)', border: 'rgba(255, 204, 77, 0.4)', color: '#ffcc4d' },
      info: { bg: 'rgba(77, 171, 247, 0.15)', border: 'rgba(77, 171, 247, 0.4)', color: '#4dabf7' }
    };
    
    const style = colors[type] || colors.info;
    el.style.background = style.bg;
    el.style.border = `1px solid ${style.border}`;
    el.style.color = style.color;
    el.innerHTML = message;
    el.style.display = 'block';
    el.classList.add('show');
  }

  function showEducationalMessage(attack, blocked = false) {
    const messages = {
      sqli: {
        success: `<strong>🚨 SQL Injection exitoso!</strong><br>
          La query fue manipulada. En la versión vulnerable, concatenar strings permite inyectar SQL arbitrario.
          <br><br><strong>Mitigación:</strong> Usa consultas preparadas (parameterized queries).`,
        blocked: `<strong>✅ SQL Injection bloqueado</strong><br>
          La versión segura usa consultas preparadas que tratan el input como datos, no como código SQL.
          <br><br><strong>Técnica:</strong> <code>query_one("SELECT * FROM users WHERE user=?", (user,))</code>`
      },
      xss: {
        success: `<strong>🚨 XSS (Cross-Site Scripting) exitoso!</strong><br>
          El JavaScript inyectado se ejecutó. Esto permite robar cookies, sesiones o modificar la página.
          <br><br><strong>Mitigación:</strong> Escapar output HTML y usar CSP (Content Security Policy).`,
        blocked: `<strong>✅ XSS bloqueado</strong><br>
          El HTML fue escapado con <code>html.escape()</code> y hay una CSP restrictiva.
          <br><br><strong>Resultado:</strong> El código se muestra como texto, no se ejecuta.`
      },
      csrf: {
        success: `<strong>⚠️ CSRF posible</strong><br>
          Sin token CSRF, un atacante podría hacer que víctimas realicen acciones sin su consentimiento.
          <br><br><strong>Mitigación:</strong> Implementar tokens CSRF únicos por sesión.`,
        blocked: `<strong>✅ CSRF protegido</strong><br>
          Se valida un token único por sesión en cada petición sensible.
          <br><br><strong>Técnica:</strong> Header <code>x-csrf-token</code> verificado en servidor.`
      },
      ssrf: {
        success: `<strong>🚨 SSRF (Server-Side Request Forgery) exitoso!</strong><br>
          El servidor realizó una petición a una URL sin validación. Esto permite acceder a recursos internos.
          <br><br><strong>Impacto:</strong> Acceso a localhost, IPs privadas, metadata cloud (169.254.169.254), servicios internos.
          <br><br><strong>Mitigación:</strong> Whitelist de dominios + validación de IPs + bloqueo de localhost.`,
        blocked: `<strong>✅ SSRF bloqueado</strong><br>
          Solo se permiten dominios específicos (whitelist) y se bloquean IPs privadas/localhost.
          <br><br><strong>Técnica:</strong> <code>ALLOWED_DOMAINS = ['example.com', ...]</code> + validación con <code>ipaddress</code>.`
      },
      pathtraversal: {
        success: `<strong>🚨 Path Traversal exitoso!</strong><br>
          Se logró acceder a archivos fuera del directorio permitido usando <code>../</code>
          <br><br><strong>Mitigación:</strong> Validar paths y usar whitelist de directorios.`,
        blocked: `<strong>✅ Path Traversal bloqueado</strong><br>
          Se rechaza cualquier path con <code>..</code> y se verifica que esté dentro del directorio base.
          <br><br><strong>Técnica:</strong> Validación con <code>os.path.abspath()</code> y comparación de prefijos.`
      },
      idor: {
        success: `<strong>🚨 IDOR (Insecure Direct Object Reference) exitoso!</strong><br>
          Accediste a datos de otro usuario sin autorización. Esto expone información privada.
          <br><br><strong>Mitigación:</strong> Verificar que el usuario autenticado tenga permiso para acceder al recurso.`,
        blocked: `<strong>✅ IDOR bloqueado</strong><br>
          Se verifica que el ID solicitado coincida con el usuario de la sesión.
          <br><br><strong>Técnica:</strong> <code>if sess["userId"] != uid: return 403</code>`
      }
    };
    
    return messages[attack]?.[blocked ? 'blocked' : 'success'] || '';
  }

  // ============================================
  // Toggle de explicaciones y pestañas
  // ============================================
  window.toggleExplanation = function(id) {
    const panel = document.getElementById(id);
    if (panel) {
      panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    }
  };
  
  window.switchTab = function(section, tab) {
    const panel = document.getElementById(section + 'Explain');
    
    // Si el panel está oculto, mostrarlo primero
    if (panel.style.display === 'none') {
      panel.style.display = 'block';
    }
    
    // Obtener todos los botones de pestaña y contenidos dentro de esta sección
    const tabButtons = panel.parentElement.querySelectorAll('.tab-btn');
    const tabContents = panel.querySelectorAll('.tab-content');
    
    // Actualizar estado de botones
    tabButtons.forEach(btn => {
      if (btn.onclick.toString().includes(`'${tab}'`)) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
    
    // Mostrar/ocultar contenido correspondiente
    tabContents.forEach(content => {
      if (content.dataset.tab === tab) {
        content.style.display = 'block';
        content.classList.add('active');
      } else {
        content.style.display = 'none';
        content.classList.remove('active');
      }
    });
  };

  window.toggleGuide = function() {
    const content = document.getElementById('guideContent');
    const icon = document.querySelector('.toggle-icon');
    if (content.style.display === 'none') {
      content.style.display = 'block';
      icon.textContent = '▲';
    } else {
      content.style.display = 'none';
      icon.textContent = '▼';
    }
  };

  // ============================================
  // LOGIN
  // ============================================
  document.getElementById('btnLogin').addEventListener('click', async () => {
    const user = document.getElementById('user').value;
    const pass = document.getElementById('pass').value;
    
    if (!user || !pass) {
      showResult('loginResult', '⚠️ Por favor ingresa usuario y contraseña', 'warning');
      return;
    }

    try {
      const res = await fetch(`/api/${mode}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user, pass })
      });
      
      const data = await res.json();
      
      // Mostrar SQL en modo vulnerable
      if (mode === 'vuln' && data.sql) {
        document.getElementById('sqlPreview').textContent = `🔍 Query SQL ejecutada:\n${data.sql}`;
        document.getElementById('sqlPreview').style.display = 'block';
      } else {
        document.getElementById('sqlPreview').style.display = 'none';
      }
      
      if (res.ok && data.ok) {
        const isSQLi = user.includes("'") || user.includes("--");
        const message = isSQLi 
          ? showEducationalMessage('sqli', isSafe)
          : `<strong>✅ Login exitoso</strong><br>Bienvenido, <code>${user}</code>`;
        showResult('loginResult', message, 'success');
        updateStatus();
      } else {
        const message = isSafe
          ? `<strong>❌ Credenciales incorrectas</strong><br>Mensaje genérico para evitar enumeración de usuarios`
          : `<strong>❌ Login fallido</strong><br>Usuario o contraseña incorrectos`;
        showResult('loginResult', message, 'error');
      }
    } catch (err) {
      showResult('loginResult', `<strong>⚠️ Error:</strong> ${err.message}`, 'error');
    }
  });

  // ============================================
  // BUSCADOR (XSS)
  // ============================================
  document.getElementById('btnSearch').addEventListener('click', async () => {
    const q = document.getElementById('q').value;
    
    if (!q) {
      showResult('searchOut', 'ℹ️ Escribe algo para buscar', 'info');
      return;
    }

    try {
      const html = await fetch(`/api/${mode}/search?q=` + encodeURIComponent(q)).then(r => r.text());
      const out = document.getElementById('searchOut');
      
      const isXSS = /<script|<img|onerror|onclick/i.test(q);
      
      if (mode === 'vuln') {
        out.innerHTML = html;
        if (isXSS) {
          setTimeout(() => {
            showResult('loginResult', showEducationalMessage('xss', false), 'error');
          }, 100);
        }
      } else {
        out.innerHTML = `<div style="padding: 14px; background: rgba(61, 220, 151, 0.1); border-radius: 8px;">
          ${html}
        </div>`;
        if (isXSS) {
          showResult('loginResult', showEducationalMessage('xss', true), 'success');
        }
      }
    } catch (err) {
      document.getElementById('searchOut').textContent = `⚠️ Error: ${err.message}`;
    }
  });

  // ============================================
  // COMENTARIOS
  // ============================================
  async function refreshComments() {
    try {
      const list = await fetch(`/api/${mode}/comments`).then(r => r.json());
      const el = document.getElementById('cList');
      el.innerHTML = '';
      
      if (list.length === 0) {
        el.innerHTML = '<li style="text-align: center; color: var(--muted);">No hay comentarios aún. ¡Sé el primero en comentar!</li>';
        return;
      }
      
      for (const c of list) {
        const li = document.createElement('li');
        if (mode === 'vuln') {
          li.innerHTML = `<b>${c.user}</b>: ${c.text} <span class="hint">${c.created_at}</span>`;
        } else {
          li.textContent = `${c.user}: ${c.text} (${c.created_at})`;
        }
        el.appendChild(li);
      }
    } catch (err) {
      console.error('Error cargando comentarios:', err);
    }
  }
  
  refreshComments();

  let csrf = null;
  async function ensureCSRF() {
    if (mode !== 'safe') return null;
    if (csrf) return csrf;
    try {
      const res = await fetch(`/api/safe/csrf`);
      if (res.ok) {
        csrf = (await res.json()).token;
      }
    } catch (err) {
      console.error('Error obteniendo CSRF token:', err);
    }
    return csrf;
  }

  document.getElementById('btnComment').addEventListener('click', async () => {
    const text = document.getElementById('cText').value;
    
    if (!text.trim()) {
      showResult('commentsResult', '⚠️ Escribe un comentario antes de publicar', 'warning');
      return;
    }

    try {
      const headers = { 'Content-Type': 'application/json' };
      
      if (mode === 'safe') {
        const token = await ensureCSRF();
        if (token) {
          headers['x-csrf-token'] = token;
        } else {
          showResult('commentsResult', '❌ Debes iniciar sesión para comentar en modo seguro', 'error');
          return;
        }
      }

      const res = await fetch(`/api/${mode}/comments`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ text })
      });

      if (res.ok) {
        const isXSS = /<script|<img|onerror|onclick/i.test(text);
        const message = isXSS 
          ? showEducationalMessage('xss', isSafe)
          : '<strong>✅ Comentario publicado</strong>';
        showResult('commentsResult', message, isXSS && !isSafe ? 'warning' : 'success');
        document.getElementById('cText').value = '';
        await refreshComments();
      } else {
        const data = await res.json();
        showResult('commentsResult', `<strong>❌ Error:</strong> ${data.error || 'No se pudo publicar'}`, 'error');
      }
    } catch (err) {
      showResult('commentsResult', `<strong>⚠️ Error:</strong> ${err.message}`, 'error');
    }
  });

  // ============================================
  // FILE UPLOAD
  // ============================================
  const fileInput = document.getElementById('fileInput');
  
  // Mostrar nombre de archivo seleccionado
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) {
      const uploadBox = document.querySelector('.upload-box');
      const icon = uploadBox.querySelector('.upload-icon');
      const info = uploadBox.querySelector('.upload-info');
      
      icon.textContent = '📄';
      uploadBox.querySelector('strong').textContent = file.name;
      info.textContent = `${(file.size / 1024).toFixed(2)} KB`;
      uploadBox.style.borderColor = 'var(--accent)';
      uploadBox.style.background = 'rgba(124, 138, 255, 0.05)';
    }
  });
  
  document.getElementById('btnUpload').addEventListener('click', async () => {
    const file = fileInput.files[0];
    
    if (!file) {
      showResult('uploadResult', '⚠️ Selecciona un archivo primero', 'warning');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`/api/${mode}/upload`, {
        method: 'POST',
        body: formData
      });

      const data = await res.json();
      
      if (res.ok) {
        const isDangerous = /\.(php|exe|sh|bat|cmd|py)$/i.test(file.name) || 
                           file.name.includes('..') || 
                           file.size > 10*1024*1024;
        
        let message = `<strong>✅ Archivo subido</strong><br>
          Nombre original: <code>${data.original || file.name}</code><br>
          Nombre guardado: <code>${data.filename}</code>`;
        
        if (!isSafe && isDangerous) {
          message += `<br><br><strong>⚠️ Vulnerabilidad explotable:</strong><br>
            • Archivo potencialmente peligroso aceptado sin validación<br>
            • Podría ejecutarse en el servidor si hay mala configuración<br>
            • Nombre original usado sin sanitizar`;
          showResult('uploadResult', message, 'warning');
        } else {
          showResult('uploadResult', message, 'success');
        }
        
        // Limpiar input
        fileInput.value = '';
        
        // Actualizar lista
        await loadUploads();
      } else {
        showResult('uploadResult', `<strong>❌ Error:</strong> ${data.error || 'Upload failed'}`, 'error');
      }
    } catch (err) {
      showResult('uploadResult', `<strong>⚠️ Error:</strong> ${err.message}`, 'error');
    }
  });

  async function loadUploads() {
    try {
      const data = await fetch(`/api/${mode}/uploads`).then(r => r.json());
      const list = document.getElementById('uploadsList');
      
      if (!data.files || data.files.length === 0) {
        list.innerHTML = '<div style="text-align: center; color: var(--muted); padding: 20px;">No hay archivos subidos</div>';
        return;
      }
      
      list.innerHTML = data.files.map(f => `
        <div class="file-item">
          <div class="file-icon">📄</div>
          <div class="file-info">
            <strong>${f.name}</strong>
            <span class="hint">${(f.size / 1024).toFixed(2)} KB • ${f.created}</span>
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.error('Error loading uploads:', err);
    }
  }
  
  loadUploads();

  // ============================================
  // SSRF (Server-Side Request Forgery)
  // ============================================
  document.getElementById('btnFetchUrl').addEventListener('click', async () => {
    const url = document.getElementById('ssrfUrl').value.trim();
    
    if (!url) {
      showResult('ssrfResult', '⚠️ Ingresa una URL', 'warning');
      return;
    }

    try {
      const res = await fetch(`/api/${mode}/fetch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      const data = await res.json();
      
      if (res.ok && data.ok) {
        let message = `<strong>✅ Contenido obtenido</strong><br>
          <strong>URL:</strong> <code>${data.url}</code><br>
          <strong>Status:</strong> ${data.status || 'OK'}<br><br>
          <div style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap;">${escapeHtml(data.content)}</div>`;
        
        if (!isSafe) {
          message += `<br><br><strong>🚨 SSRF Vulnerable Detectado!</strong><br>
            • El servidor hizo una petición sin validación<br>
            • Podrías acceder a localhost o IPs privadas<br>
            • Riesgo: lectura de metadata cloud, servicios internos<br>
            • Sin whitelist de dominios permitidos`;
          showResult('ssrfResult', message, 'error');
          showResult('loginResult', showEducationalMessage('ssrf', false), 'error');
        } else {
          showResult('ssrfResult', message, 'success');
          showResult('loginResult', showEducationalMessage('ssrf', true), 'success');
        }
      } else {
        const message = `<strong>❌ Error:</strong> ${data.error || 'Fetch failed'}`;
        if (isSafe && res.status === 403) {
          showResult('ssrfResult', message + '<br><br>✅ <strong>Whitelist activa</strong> - Solo dominios permitidos: example.com, httpbin.org, jsonplaceholder.typicode.com', 'error');
          showResult('loginResult', showEducationalMessage('ssrf', true), 'success');
        } else {
          showResult('ssrfResult', message, 'error');
        }
      }
    } catch (err) {
      showResult('ssrfResult', `<strong>⚠️ Error:</strong> ${err.message}`, 'error');
    }
  });

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  // Cargar perfil inicial
  setTimeout(showProfile, 500);

  // ============================================
  // ARCHIVOS (Eliminado - reemplazado por Upload)
  // ============================================
  // El módulo de path traversal fue reemplazado por File Upload

  // ============================================
  // PROFILE IDOR (Eliminado - reemplazado por Mass Assignment)
  // ============================================
  // El módulo de IDOR fue reemplazado por Mass Assignment

  // ============================================
  // VISOR DE CÓDIGO
  // ============================================
  document.getElementById('btnCode').addEventListener('click', async () => {
    const file = document.getElementById('codeFile').value;
    console.log('📖 Comparando código de:', file);
    
    // Mostrar loading
    document.getElementById('codeVuln').textContent = '⏳ Cargando código vulnerable...';
    document.getElementById('codeSafe').textContent = '⏳ Cargando código seguro...';
    
    try {
      console.log('🔍 Haciendo peticiones a los endpoints...');
      const [vulnRes, safeRes] = await Promise.all([
        fetch(`/api/vuln/code?file=${encodeURIComponent(file)}`),
        fetch(`/api/safe/code?file=${encodeURIComponent(file)}`)
      ]);
      
      console.log('📥 Respuestas recibidas - Vulnerable:', vulnRes.status, 'Seguro:', safeRes.status);
      
      const vulnData = await vulnRes.json();
      const safeData = await safeRes.json();
      
      console.log('✅ Datos parseados:', {
        vuln: vulnData.code ? `${vulnData.code.length} caracteres` : vulnData.error,
        safe: safeData.code ? `${safeData.code.length} caracteres` : safeData.error
      });
      
      const vulnCode = vulnData.code || vulnData.error || 'Error al cargar';
      const safeCode = safeData.code || safeData.error || 'Error al cargar';
      
      document.getElementById('codeVuln').textContent = vulnCode;
      document.getElementById('codeSafe').textContent = safeCode;
      
      console.log('✨ Código mostrado en pantalla');
      
      // Mensaje educativo
      if (vulnData.code && !vulnData.error) {
        const msg = !isSafe 
          ? showEducationalMessage('pathtraversal', false)
          : showEducationalMessage('pathtraversal', true);
        showResult('loginResult', msg, !isSafe ? 'error' : 'success');
      }
    } catch (err) {
      console.error('❌ Error cargando código:', err);
      document.getElementById('codeVuln').textContent = `❌ Error: ${err.message}`;
      document.getElementById('codeSafe').textContent = `❌ Error: ${err.message}`;
    }
  });

  // ============================================
  // Inicialización
  // ============================================
  console.log(`%c🛡️ Laboratorio de Seguridad Web`, 'font-size: 20px; font-weight: bold; color: #7c8aff;');
  console.log(`%cModo activo: ${mode.toUpperCase()}`, 'font-size: 14px; color: ' + (isSafe ? '#3ddc97' : '#ff6b6b'));
  console.log('%cEste es un entorno educativo. Explora las vulnerabilidades de forma responsable.', 'color: #9aa3c7;');
})();