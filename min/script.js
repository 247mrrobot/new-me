/* =======================================================
   ELECTROVOTE CLIENT — talks to Python server only
   ======================================================= */

// ---------- Utilities ----------
function escapeHTML(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// In-memory token (cleared when tab closes — XSS can't grab it from storage)
let sessionToken = sessionStorage.getItem('token') || null;

function setToken(t) {
    sessionToken = t;
    if (t) sessionStorage.setItem('token', t);
    else sessionStorage.removeItem('token');
}

async function api(path, method = 'GET', body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (sessionToken) headers['X-Session-Token'] = sessionToken;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
}

// ---------- Auto logout after 15 min inactivity ----------
let lastActivity = Date.now();
['click', 'keydown', 'mousemove'].forEach(evt =>
    document.addEventListener(evt, () => lastActivity = Date.now())
);
setInterval(() => {
    if (sessionToken && Date.now() - lastActivity > 15 * 60 * 1000) {
        setToken(null);
        window.location.href = 'index.html';
    }
}, 30_000);

/* =======================================================
   STUDENT LOGIN (index.html)
   ======================================================= */
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const index_num = document.getElementById('indexNum').value.trim();
        const full_name = document.getElementById('fullName').value.trim();
        const errorMsg = document.getElementById('errorMsg');
        errorMsg.textContent = '';

        const { ok, data } = await api('/api/login', 'POST', { index_num, full_name });
        if (ok) {
            setToken(data.token);
            window.location.href = 'vote.html';
        } else {
            errorMsg.textContent = data.error || 'Login failed';
        }
    });
}

/* =======================================================
   ADMIN LOGIN (admin.html — you'll add this form)
   ======================================================= */
const adminLoginForm = document.getElementById('adminLoginForm');
if (adminLoginForm) {
    adminLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('adminPass').value;
        const errorMsg = document.getElementById('adminError');
        errorMsg.textContent = '';

        const { ok, data } = await api('/api/admin/login', 'POST', { password });
        if (ok) {
            setToken(data.token);
            document.getElementById('adminLoginBox').classList.add('hidden');
            document.getElementById('adminPanel').classList.remove('hidden');
            loadStudents();
        } else {
            errorMsg.textContent = data.error || 'Login failed';
        }
    });
}

/* =======================================================
   ADMIN ACTIONS
   ======================================================= */
function showTab(tabName) {
    // Hide every tab content and remove active state
    document.querySelectorAll('.tab-content, .tabcontent').forEach(t => {
        t.classList.add('hidden');
        t.classList.remove('active');
    });
    // Show the selected tab
    const tab = document.getElementById(tabName + 'Tab');
    if (tab) {
        tab.classList.remove('hidden');
        tab.classList.add('active');
    }
    // Load the data for the selected tab
    if (tabName === 'students') loadStudents();
    if (tabName === 'positions') loadPositions();
    if (tabName === 'candidates') loadCandidateForm();
}

// --- Students ---
async function loadStudents() {
    const { ok, data } = await api('/api/admin/students');
    if (!ok) return;
    const tbody = document.querySelector('#studentsTable tbody');
    tbody.innerHTML = data.students.map(s => `
        <tr>
            <td>${escapeHTML(s.index_num)}</td>
            <td>${escapeHTML(s.full_name)}</td>
            <td>${s.voted ? '✅' : '❌'}</td>
            <td><button class="delete-btn" onclick="deleteStudent(${s.id})">Delete</button></td>
        </tr>
    `).join('');
}

async function addStudent() {
    const index_num = document.getElementById('studentIndex').value.trim();
    const full_name = document.getElementById('studentName').value.trim();
    if (!index_num || !full_name) return alert('Fill both fields');
    const { ok, data } = await api('/api/admin/students', 'POST', { index_num, full_name });
    if (ok) {
        document.getElementById('studentIndex').value = '';
        document.getElementById('studentName').value = '';
        loadStudents();
    } else alert(data.error);
}

async function deleteStudent(id) {
    if (!confirm('Delete this student?')) return;
    await api('/api/admin/students/' + id, 'DELETE');
    loadStudents();
}

// --- Positions ---
async function loadPositions() {
    const { ok, data } = await api('/api/admin/positions');
    if (!ok) return;
    const list = document.getElementById('positionsList');
    list.innerHTML = data.positions.map(p => `
        <li style="margin: 10px 0; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 8px; display:flex; justify-content:space-between;">
            <span>${escapeHTML(p.title)} (Order: ${p.sort_order})</span>
            <button class="delete-btn" onclick="deletePosition(${p.id})">Delete</button>
        </li>
    `).join('');
}

async function addPosition() {
    const title = document.getElementById('positionTitle').value.trim();
    const sort_order = parseInt(document.getElementById('positionOrder').value) || 0;
    if (!title) return alert('Enter title');
    const { ok, data } = await api('/api/admin/positions', 'POST', { title, sort_order });
    if (ok) {
        document.getElementById('positionTitle').value = '';
        loadPositions();
        loadCandidateForm();
    } else alert(data.error);
}

async function deletePosition(id) {
    if (!confirm('Delete this position and its candidates?')) return;
    await api('/api/admin/positions/' + id, 'DELETE');
    loadPositions();
    loadCandidateForm();
}

// --- Candidates ---
async function loadCandidateForm() {
    const { ok, data } = await api('/api/admin/positions');
    if (!ok) return;
    const select = document.getElementById('candidatePosition');
    select.innerHTML = data.positions.map(p =>
        `<option value="${p.id}">${escapeHTML(p.title)}</option>`
    ).join('');
    if (data.positions.length) {
        select.onchange = () => loadCandidatesList(select.value);
        loadCandidatesList(data.positions[0].id);
    }
}

async function loadCandidatesList(posId) {
    const { ok, data } = await api('/api/admin/candidates');
    if (!ok) return;
    const filtered = data.candidates.filter(c => c.position_id == posId);
    const list = document.getElementById('candidatesList');
    list.innerHTML = filtered.map(c => `
        <div style="display:flex; align-items:center; gap:15px; margin:10px 0; padding:10px; background:rgba(255,255,255,0.05); border-radius:8px;">
            <img src="${c.image_url || 'https://via.placeholder.com/150'}" width="40" height="40" style="border-radius:50%; object-fit:cover;">
            <strong>${escapeHTML(c.name)}</strong>
            <button class="delete-btn" style="margin-left:auto;" onclick="deleteCandidate(${c.id})">Delete</button>
        </div>
    `).join('') || '<p>No candidates yet.</p>';
}

let pendingImageBase64 = null;

function addCandidate() {
    const posId = document.getElementById('candidatePosition').value;
    const name = document.getElementById('candidateName').value.trim();
    const fileInput = document.getElementById('candidateImage');

    if (!posId || !name) return alert('Select position and enter name');

    if (fileInput.files && fileInput.files[0]) {
        const reader = new FileReader();
        reader.onload = (event) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.createElement('canvas');
                const MAX = 300;
                let w = img.width, h = img.height;
                if (w > h) { if (w > MAX) { h *= MAX / w; w = MAX; } }
                else { if (h > MAX) { w *= MAX / h; h = MAX; } }
                canvas.width = w; canvas.height = h;
                canvas.getContext('2d').drawImage(img, 0, 0, w, h);
                pendingImageBase64 = canvas.toDataURL('image/jpeg', 0.8);
                submitCandidate(posId, name, pendingImageBase64);
            };
            img.src = event.target.result;
        };
        reader.readAsDataURL(fileInput.files[0]);
    } else {
        submitCandidate(posId, name, '');
    }
}

async function submitCandidate(posId, name, imageBase64) {
    const { ok, data } = await api('/api/admin/candidates', 'POST', {
        position_id: parseInt(posId),
        name,
        image_url: imageBase64
    });
    if (ok) {
        document.getElementById('candidateName').value = '';
        document.getElementById('candidateImage').value = '';
        document.getElementById('fileNameDisplay').textContent = 'No file selected';
        loadCandidatesList(posId);
        alert('Candidate added!');
    } else alert(data.error);
}

async function deleteCandidate(id) {
    if (!confirm('Delete this candidate?')) return;
    await api('/api/admin/candidates/' + id, 'DELETE');
    const posId = document.getElementById('candidatePosition').value;
    loadCandidatesList(posId);
}

// Filename display
const fileInput = document.getElementById('candidateImage');
if (fileInput) {
    fileInput.addEventListener('change', function () {
        const display = document.getElementById('fileNameDisplay');
        if (this.files && this.files[0]) {
            display.textContent = '✅ ' + this.files[0].name;
            display.style.color = 'var(--neon-green)';
        } else {
            display.textContent = 'No file selected';
            display.style.color = '';
        }
    });
}

async function logout() {
    await api('/api/admin/logout', 'POST');
    setToken(null);
    window.location.reload();
}