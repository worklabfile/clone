#!/usr/bin/env node

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const url = require('url');
const querystring = require('querystring');

const PORT = 8080;
const DATA_PATH = __dirname + '/data';

// Утилиты
function loadJSON(filePath) {
    if (!fs.existsSync(filePath)) return {};
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return {};
    try {
        return JSON.parse(raw);
    } catch (e) {
        return {};
    }
}

function saveJSON(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function hashPassword(password, salt) {
    return crypto.createHmac('sha256', salt).update(password).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getCurrentUser(token) {
    const users = loadJSON(DATA_PATH + '/users.json');
    for (let user in users) {
        if (users[user].token === token) {
            return { username: user, data: users[user] };
        }
    }
    return null;
}

// Начальная инициализация файлов
if (!fs.existsSync(DATA_PATH)) {
    fs.mkdirSync(DATA_PATH);
}
if (!fs.existsSync(DATA_PATH + '/users.json')) {
    saveJSON(DATA_PATH + '/users.json', {});
}
if (!fs.existsSync(DATA_PATH + '/notes.json')) {
    saveJSON(DATA_PATH + '/notes.json', {});
}
if (!fs.existsSync(DATA_PATH + '/groups.json')) {
    saveJSON(DATA_PATH + '/groups.json', {});
}

// Маршруты
function handleRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    let body = '';

    req.on('data', chunk => {
        body += chunk;
    });

    req.on('end', () => {
        const users = loadJSON(DATA_PATH + '/users.json');
        const notes = loadJSON(DATA_PATH + '/notes.json');
        const groups = loadJSON(DATA_PATH + '/groups.json');

        if (path === '/register' && req.method === 'POST') {
            const params = querystring.parse(body);
            const username = (params.username || '').trim();
            const password = (params.password || '').trim();
            if (!username || !password) {
                res.writeHead(400);
                return res.end('Username and password required');
            }
            if (users[username]) {
                res.writeHead(400);
                return res.end('User already exists');
            }
            const salt = crypto.randomBytes(16).toString('hex');
            const passHash = hashPassword(password, salt);
            users[username] = {
                salt: salt,
                password: passHash,
                token: '',
                groups: []
            };
            saveJSON(DATA_PATH + '/users.json', users);
            res.writeHead(200);
            return res.end('OK');
        }

        if (path === '/login' && req.method === 'POST') {
            const params = querystring.parse(body);
            const username = (params.username || '').trim();
            const password = (params.password || '').trim();
            if (!users[username]) {
                res.writeHead(400);
                return res.end('User not found');
            }
            const salt = users[username].salt;
            const passHash = hashPassword(password, salt);
            if (users[username].password === passHash) {
                const token = generateToken();
                users[username].token = token;
                saveJSON(DATA_PATH + '/users.json', users);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ token }));
            } else {
                res.writeHead(401);
                return res.end('Invalid password');
            }
        }

        if (path === '/logout' && req.method === 'POST') {
            const params = querystring.parse(body);
            const token = params.token;
            const currentUser = getCurrentUser(token);
            if (currentUser) {
                users[currentUser.username].token = '';
                saveJSON(DATA_PATH + '/users.json', users);
                res.writeHead(200);
                return res.end('OK');
            } else {
                res.writeHead(401);
                return res.end('Invalid token');
            }
        }

        if (path === '/add_note' && req.method === 'POST') {
            const params = querystring.parse(body);
            const token = params.token;
            const note = params.note || '';
            const noteUrl = params.url || '';
            const currentUser = getCurrentUser(token);
            if (!currentUser) {
                res.writeHead(401);
                return res.end('Invalid token');
            }
            // Сохраняем заметку для пользователя
            if (!notes[currentUser.username]) {
                notes[currentUser.username] = [];
            }
            notes[currentUser.username].push({
                url: noteUrl,
                note: note,
                group: null // личная заметка
            });
            saveJSON(DATA_PATH + '/notes.json', notes);
            res.writeHead(200);
            return res.end('OK');
        }

        if (path === '/get_notes' && req.method === 'POST') {
            const params = querystring.parse(body);
            const token = params.token;
            const noteUrl = params.url || '';
            const currentUser = getCurrentUser(token);
            if (!currentUser) {
                res.writeHead(401);
                return res.end('Invalid token');
            }
            let userNotes = notes[currentUser.username] || [];
            // Заметки пользователя
            userNotes = userNotes.filter(n => n.url === noteUrl && !n.group);
            // Заметки групп, в которых он состоит
            const userGroups = currentUser.data.groups || [];
            let groupNotes = [];
            for (let g of userGroups) {
                if (groups[g] && groups[g].notes) {
                    groupNotes = groupNotes.concat(groups[g].notes.filter(n => n.url === noteUrl));
                }
            }
            const allNotes = userNotes.concat(groupNotes);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify(allNotes));
        }

        if (path === '/create_group' && req.method === 'POST') {
            const params = querystring.parse(body);
            const token = params.token;
            const groupName = params.group_name || '';
            const currentUser = getCurrentUser(token);
            if (!currentUser || !groupName) {
                res.writeHead(400);
                return res.end('Bad request');
            }
            if (groups[groupName]) {
                res.writeHead(400);
                return res.end('Group already exists');
            }
            groups[groupName] = {
                admin: currentUser.username,
                members: [currentUser.username],
                notes: []
            };
            // Добавляем группу пользователю
            users[currentUser.username].groups.push(groupName);
            saveJSON(DATA_PATH + '/users.json', users);
            saveJSON(DATA_PATH + '/groups.json', groups);
            res.writeHead(200);
            return res.end('OK');
        }

        if (path === '/join_group' && req.method === 'POST') {
            const params = querystring.parse(body);
            const token = params.token;
            const groupName = params.group_name || '';
            const currentUser = getCurrentUser(token);
            if (!currentUser || !groupName || !groups[groupName]) {
                res.writeHead(400);
                return res.end('Bad request');
            }
            const g = groups[groupName];
            if (g.members.indexOf(currentUser.username) === -1) {
                g.members.push(currentUser.username);
                users[currentUser.username].groups.push(groupName);
                saveJSON(DATA_PATH + '/users.json', users);
                saveJSON(DATA_PATH + '/groups.json', groups);
            }
            res.writeHead(200);
            return res.end('OK');
        }

        if (path === '/add_group_note' && req.method === 'POST') {
            const params = querystring.parse(body);
            const token = params.token;
            const note = params.note || '';
            const noteUrl = params.url || '';
            const groupName = params.group_name || '';
            const currentUser = getCurrentUser(token);
            if (!currentUser || !groups[groupName]) {
                res.writeHead(400);
                return res.end('Bad request');
            }
            const g = groups[groupName];
            // Проверяем права (только админ может добавлять/редактировать)
            if (g.admin !== currentUser.username) {
                res.writeHead(403);
                return res.end('Forbidden');
            }
            g.notes.push({
                url: noteUrl,
                note: note
            });
            saveJSON(DATA_PATH + '/groups.json', groups);
            res.writeHead(200);
            return res.end('OK');
        }

        res.writeHead(404);
        return res.end('Not Found');
    });
}

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
