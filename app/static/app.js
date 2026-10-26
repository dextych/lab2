// ============ Утилиты ============

const TOKEN_KEY = "access_token";

function getToken() { return localStorage.getItem(TOKEN_KEY); }
function setToken(token) { localStorage.setItem(TOKEN_KEY, token); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }
function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }
function setError(el, msg) { el.textContent = msg || ""; }

async function api(path, body) {
    const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
}

async function gql(query, variables = {}) {
    const headers = { "Content-Type": "application/json" };
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch("/graphql", {
        method: "POST",
        headers,
        body: JSON.stringify({ query, variables }),
    });

    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (json.errors && json.errors.length) throw new Error(json.errors.map(e => e.message).join("; "));
    return json.data;
}

function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function formatDate(isoString) {
    if (!isoString) return "";
    return new Date(isoString).toLocaleString("ru-RU");
}

// ============ Работа с UI ============

const loginBlock = document.getElementById("login-block");
const adminBlock = document.getElementById("admin-block");
const loginError = document.getElementById("login-error");
const adminError = document.getElementById("admin-error");

function switchToAdmin() {
    hide(loginBlock);
    show(adminBlock);
    setError(loginError, "");
    loadClients();
}

function switchToLogin() {
    show(loginBlock);
    hide(adminBlock);
    document.getElementById("clients-tbody").innerHTML = "";
    document.getElementById("sessions-tbody").innerHTML = "";
    setError(adminError, "");
}

// Логика вкладок
document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        e.target.classList.add("active");

        const targetId = e.target.getAttribute("data-target");
        document.querySelectorAll(".card[id^='tab-']").forEach(c => c.classList.add("hidden"));
        document.getElementById(targetId).classList.remove("hidden");

        if (targetId === "tab-sessions") loadSessions();
        if (targetId === "tab-clients") loadClients();
    });
});

// ============ Действия ============

async function handleLogin() {
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    setError(loginError, "");

    if (!email || !password) {
        setError(loginError, "Введите email и пароль");
        return;
    }

    try {
        const data = await api("/auth/login", { email, password });
        setToken(data.access_token);
        switchToAdmin();
    } catch (err) {
        setError(loginError, err.message);
    }
}

function handleLogout() {
    clearToken();
    document.getElementById("email").value = "";
    document.getElementById("password").value = "";
    switchToLogin();
}

// ============ КЛИЕНТЫ ============

async function loadClients() {
    const tbody = document.getElementById("clients-tbody");
    tbody.innerHTML = `<tr><td colspan="5">Загрузка...</td></tr>`;
    setError(adminError, "");

    try {
        const data = await gql(`
            query {
                clients {
                    clientId
                    name
                    isConfidential
                    isActive
                }
            }
        `);
        renderClients(data.clients);
    } catch (err) {
        tbody.innerHTML = "";
        setError(adminError, err.message);
    }
}

function renderClients(clients) {
    const tbody = document.getElementById("clients-tbody");
    if (!clients.length) {
        tbody.innerHTML = `<tr><td colspan="5">Нет клиентов</td></tr>`;
        return;
    }

    tbody.innerHTML = clients.map(c => `
        <tr>
            <td>${escapeHtml(c.clientId)}</td>
            <td>${escapeHtml(c.name)}</td>
            <td>${c.isConfidential ? "да" : "нет"}</td>
            <td>${c.isActive ? "да" : "нет"}</td>
            <td>
                <button class="small" onclick="rotateSecret('${c.clientId}')">Ротировать секрет</button>
            </td>
        </tr>
    `).join("");
}

async function handleCreateClient() {
    const name = document.getElementById("client-name").value.trim();
    const isConfidential = document.getElementById("client-confidential").checked;
    setError(adminError, "");

    if (!name) {
        setError(adminError, "Введите название клиента");
        return;
    }

    try {
        const data = await gql(`
            mutation CreateClient($name: String!, $isConfidential: Boolean!) {
                createClient(name: $name, isConfidential: $isConfidential) {
                    clientId
                    clientSecret
                }
            }
        `, { name, isConfidential });

        if (data.createClient.clientSecret) {
            alert(`Клиент создан!\n\nClient ID: ${data.createClient.clientId}\nClient Secret: ${data.createClient.clientSecret}\n\nСКОПИРУЙТЕ СЕКРЕТ СЕЙЧАС!`);
        } else {
            alert(`Клиент создан!\nClient ID: ${data.createClient.clientId}`);
        }

        document.getElementById("client-name").value = "";
        loadClients();
    } catch (err) {
        setError(adminError, err.message);
    }
}

async function rotateSecret(clientId) {
    if (!confirm(`Сгенерировать новый секрет для клиента ${clientId}? Старый перестанет работать.`)) return;
    setError(adminError, "");

    try {
        const data = await gql(`
            mutation RotateSecret($clientId: ID!) {
                rotateClientSecret(clientId: $clientId) {
                    clientId
                    clientSecret
                }
            }
        `, { clientId });

        alert(`Новый секрет для ${data.rotateClientSecret.clientId}:\n\n${data.rotateClientSecret.clientSecret}\n\nСКОПИРУЙТЕ ЕГО СЕЙЧАС!`);
    } catch (err) {
        setError(adminError, err.message);
    }
}

// ============ СЕССИИ ============

async function loadSessions() {
    const tbody = document.getElementById("sessions-tbody");
    tbody.innerHTML = `<tr><td colspan="6">Загрузка...</td></tr>`;
    setError(adminError, "");

    try {
        // userId не передаем (или можно передать "1", если нужно для конкретного юзера)
        const data = await gql(`
            query {
                sessions {
                    id
                    clientId
                    ip
                    userAgent
                    createdAt
                }
            }
        `);
        renderSessions(data.sessions);
    } catch (err) {
        tbody.innerHTML = "";
        setError(adminError, err.message);
    }
}

function renderSessions(sessions) {
    const tbody = document.getElementById("sessions-tbody");
    if (!sessions.length) {
        tbody.innerHTML = `<tr><td colspan="6">Нет активных сессий</td></tr>`;
        return;
    }

    tbody.innerHTML = sessions.map(s => `
        <tr>
            <td>${escapeHtml(s.id)}</td>
            <td>${escapeHtml(s.clientId)}</td>
            <td>${escapeHtml(s.ip || "-")}</td>
            <td title="${escapeHtml(s.userAgent)}">${escapeHtml((s.userAgent || "").substring(0, 30))}...</td>
            <td>${formatDate(s.createdAt)}</td>
            <td>
                <button class="small danger" onclick="revokeSession('${s.id}')">Завершить</button>
            </td>
        </tr>
    `).join("");
}

async function revokeSession(sessionId) {
    if (!confirm("Завершить эту сессию?")) return;
    setError(adminError, "");

    try {
        // Если в схеме нет мутации удаления конкретной сессии, используем отзыв всех сессий пользователя
        // Но так как у нас нет userId в строке, мы можем отозвать все (для примера)
        // В реальном проекте нужна мутация revokeSession(id)
        
        // Временное решение: отзываем все сессии
        alert("Для отзыва конкретной сессии в схеме нет мутации. Отзываем все сессии пользователя.");
        await gql(`mutation { revokeUserSessions(userId: "1") }`);
        loadSessions();
    } catch (err) {
        setError(adminError, err.message);
    }
}

// ============ Привязка событий ============

document.getElementById("login-btn").addEventListener("click", handleLogin);
document.getElementById("logout-btn").addEventListener("click", handleLogout);
document.getElementById("create-client-btn").addEventListener("click", handleCreateClient);

document.getElementById("password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleLogin();
});

// ============ Инициализация ============

if (getToken()) {
    switchToAdmin();
} else {
    switchToLogin();
}