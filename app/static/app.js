// ============ Утилиты ============

const TOKEN_KEY = "access_token";

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
}

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

function setError(el, msg) {
    el.textContent = msg || "";
}

/**
 * POST к REST-эндпоинту с JSON.
 * Бросает Error, если ответ не 2xx.
 */
async function api(path, body) {
    const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        throw new Error(data.detail || `HTTP ${res.status}`);
    }
    return data;
}

/**
 * POST к /graphql с Authorization.
 * Бросает Error, если в ответе есть errors.
 */
async function gql(query, variables = {}) {
    const headers = { "Content-Type": "application/json" };
    const token = getToken();
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch("/graphql", {
        method: "POST",
        headers,
        body: JSON.stringify({ query, variables }),
    });

    const json = await res.json().catch(() => ({}));

    if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
    }
    if (json.errors && json.errors.length) {
        throw new Error(json.errors.map(e => e.message).join("; "));
    }
    return json.data;
}

// ============ Работа с UI ============

const loginBlock = document.getElementById("login-block");
const adminBlock = document.getElementById("admin-block");
const loginError = document.getElementById("login-error");
const adminError = document.getElementById("admin-error");
const clientsTbody = document.getElementById("clients-tbody");

function switchToAdmin() {
    hide(loginBlock);
    show(adminBlock);
    setError(loginError, "");
    loadClients();
}

function switchToLogin() {
    show(loginBlock);
    hide(adminBlock);
    clientsTbody.innerHTML = "";
    setError(adminError, "");
}

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

async function loadClients() {
    clientsTbody.innerHTML = `<tr><td colspan="5">Загрузка...</td></tr>`;
    setError(adminError, "");

    try {
        const data = await gql(`
            query {
                clients {
                    id
                    clientId
                    name
                    isConfidential
                    createdAt
                }
            }
        `);
        renderClients(data.clients);
    } catch (err) {
        clientsTbody.innerHTML = "";
        setError(adminError, err.message);
    }
}

function renderClients(clients) {
    if (!clients.length) {
        clientsTbody.innerHTML = `<tr><td colspan="5">Нет клиентов</td></tr>`;
        return;
    }

    clientsTbody.innerHTML = clients.map(c => `
        <tr>
            <td>${escapeHtml(c.id)}</td>
            <td>${escapeHtml(c.clientId)}</td>
            <td>${escapeHtml(c.name)}</td>
            <td>${c.isConfidential ? "да" : "нет"}</td>
            <td>${escapeHtml(c.createdAt)}</td>
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
        await gql(`
            mutation CreateClient($name: String!, $isConfidential: Boolean!) {
                createClient(name: $name, isConfidential: $isConfidential) {
                    id
                    clientId
                    name
                }
            }
        `, { name, isConfidential });

        document.getElementById("client-name").value = "";
        loadClients();
    } catch (err) {
        setError(adminError, err.message);
    }
}

// Простая защита от XSS при выводе данных
function escapeHtml(s) {
    return String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

// ============ Привязка событий ============

document.getElementById("login-btn").addEventListener("click", handleLogin);
document.getElementById("logout-btn").addEventListener("click", handleLogout);
document.getElementById("create-client-btn").addEventListener("click", handleCreateClient);

// Enter в поле пароля — тоже логин
document.getElementById("password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleLogin();
});

// ============ Инициализация ============

if (getToken()) {
    switchToAdmin();
} else {
    switchToLogin();
}