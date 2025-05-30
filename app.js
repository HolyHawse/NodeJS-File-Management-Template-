const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();
const http = require('http');
const https = require('https');
const fs = require('fs');
const db = new sqlite3.Database('./data/sql.db');
const PORT = process.env.PORT || 4444;
const multer = require('multer');
const filesUpload = multer({ dest: path.join(__dirname, 'public', 'uploads'), limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB

app.set('views', path.join(__dirname, 'public', 'html'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false
}));

function renderWithLayout(res, view, options = {}) {
    const layout = options.layout === false ? false : 'layout';
    if (layout) {
        require('ejs').renderFile(
            path.join(__dirname, 'public', 'html', view + '.ejs'),
            options,
            (err, str) => {
                if (err) return res.status(500).send('EJS render error: ' + err);
                res.render(layout, { ...options, body: str });
            }
        );
    } else {
        res.render(view, options);
    }
}

// Kullanıcı giriş kontrolü
function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
}
// Admin kontrolü
function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.status(403).render('error', { user: req.session.user, error: 'Bu sayfaya erişim yetkiniz yok.', title: '403 - Yetkisiz Erişim', layout: false });
    }
    next();
}

// Ana sayfa
app.get('/', (req, res) => {
    renderWithLayout(res, 'main', { user: req.session.user, activePage: 'main', title: 'WebReport Ana Sayfa' });
});

// Login
app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.render('login', { layout: false, error: null, message: null });
});
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT id, username, password, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE username = ?', [username], (err, user) => {
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            res.redirect('/');
        } else {
            res.render('login', { layout: false, error: 'Hatalı giriş!', message: null });
        }
    });
});

// Register
app.post('/register', (req, res) => {
    const { username, password, name, surname, email, tckimlikno } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (user) {
            res.render('login', { layout: false, error: 'Kullanıcı adı mevcut!', message: null });
        } else {
            const hash = bcrypt.hashSync(password, 10);
            db.run('INSERT INTO users (username, password, name, surname, email, tckimlikno, isAdmin) VALUES (?, ?, ?, ?, ?, ?, 0)',
                [username, hash, name, surname, email, tckimlikno], function (err) {
                    if (err) return res.render('login', { layout: false, error: 'Kayıt hatası!', message: null });
                    res.render('login', { layout: false, error: null, message: 'Kayıt başarılı, giriş yapabilirsiniz.' });
                });
        }
    });
});

// Kullanıcılar (admin)
app.get('/users', requireAdmin, (req, res) => {
    db.all('SELECT * FROM users WHERE active = 1', [], (err, activeUsers) => {
        db.all('SELECT * FROM users WHERE active = 0', [], (err2, deletedUsers) => {
            activeUsers = (activeUsers || []).map(u => ({
                ...u,
                id: Number(u.id),
                isAdmin: Number(u.isAdmin)
            }));
            deletedUsers = (deletedUsers || []).map(u => ({
                ...u,
                id: Number(u.id),
                isAdmin: Number(u.isAdmin)
            }));
            renderWithLayout(res, 'users', {
                user: req.session.user,
                activeUsers,
                deletedUsers,
                activePage: 'users',
                title: 'Kullanıcılar'
            });
        });
    });
});

// Kullanıcı düzenle
app.post('/edit-user', requireAdmin, (req, res) => {
    const { id, name, surname, tckimlikno, email, phone, username, password, isAdmin } = req.body;
    db.get('SELECT id FROM users WHERE (username = ? OR tckimlikno = ?) AND id != ?', [username, tckimlikno, id], (err, row) => {
        if (row) {
            return res.redirect('/users?editError=Bu kullanıcı adı veya TC Kimlik No başka bir kullanıcıda mevcut!');
        }
        if (password && password.trim() !== '') {
            const hash = bcrypt.hashSync(password, 10);
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=?, password=?, isAdmin=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, hash, isAdmin, id], function (err) {
                    res.redirect('/users');
                });
        } else {
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=?, isAdmin=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, isAdmin, id], function (err) {
                    res.redirect('/users');
                });
        }
    });
});

// Kullanıcı sil
app.post('/delete-user', requireAdmin, (req, res) => {
    const { id } = req.body;
    db.run('UPDATE users SET active=0 WHERE id=?', [id], function (err) {
        res.redirect('/users');
    });
});

// Kullanıcı tekrar aktif et
app.post('/activate-user', requireAdmin, (req, res) => {
    const { id } = req.body;
    db.run('UPDATE users SET active=1 WHERE id=?', [id], function (err) {
        res.redirect('/users');
    });
});

// Profil
app.get('/profile', requireLogin, (req, res) => {
    db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [req.session.user.id], (err, user) => {
        renderWithLayout(res, 'profile', { user, activePage: 'profile', title: 'Profilim' });
    });
});
app.post('/edit-profile', requireLogin, (req, res) => {
    const { id, name, surname, tckimlikno, email, phone, username, password } = req.body;
    db.get('SELECT id FROM users WHERE (username = ? OR tckimlikno = ?) AND id != ?', [username, tckimlikno, id], (err, row) => {
        if (row) {
            db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [id], (err2, user) => {
                return renderWithLayout(res, 'profile', { user, activePage: 'profile', title: 'Profilim', editError: 'Bu kullanıcı adı veya TC Kimlik No başka bir kullanıcıda mevcut!' });
            });
            return;
        }
        if (password && password.trim() !== '') {
            const hash = bcrypt.hashSync(password, 10);
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=?, password=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, hash, id], function (err) {
                    db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [id], (err2, user) => {
                        req.session.user = user;
                        res.redirect('/profile');
                    });
                });
        } else {
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, id], function (err) {
                    db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [id], (err2, user) => {
                        req.session.user = user;
                        res.redirect('/profile');
                    });
                });
        }
    });
});

// İletişim
app.get('/contact', (req, res) => {
    db.all('SELECT * FROM contacts ORDER BY DATE DESC', [], (err, contacts) => {
        renderWithLayout(res, 'contact', { user: req.session.user, contacts, activePage: 'contact', title: 'İletişim' });
    });
});
app.post('/contact', (req, res) => {
    const { mail, message } = req.body;
    db.run('INSERT INTO contacts (MAIL, MESSAGE, DATE) VALUES (?, ?, datetime("now","localtime"))', [mail, message], (err) => {
        db.all('SELECT * FROM contacts ORDER BY DATE DESC', [], (err2, contacts) => {
            renderWithLayout(res, 'contact', {
                user: req.session.user,
                contacts,
                message: err ? 'Kayıt hatası!' : 'Mesajınız kaydedildi.',
                activePage: 'contact',
                title: 'İletişim'
            });
        });
    });
});
app.post('/delete-contact', requireAdmin, (req, res) => {
    const { id } = req.body;
    db.run('DELETE FROM contacts WHERE id = ?', [id], function (err) {
        res.redirect('/dashboard');
    });
});

// Dashboard (admin, iletişim mesajları)
app.get('/dashboard', requireAdmin, (req, res) => {
    const pageSize = 12;
    const pageNo = Number(req.query.ContactPage) || 1;
    db.all('SELECT COUNT(*) as total FROM contacts', [], (err, countRows) => {
        const totalContacts = countRows[0].total;
        const contactsTotalPages = Math.ceil(totalContacts / pageSize);
        db.all('SELECT * FROM contacts ORDER BY DATE DESC LIMIT ? OFFSET ?', [pageSize, (pageNo - 1) * pageSize], (err2, contactsPage) => {
            renderWithLayout(res, 'dashboard', {
                user: req.session.user,
                contactsPage,
                contactsTotalPages,
                ContactPageNo: pageNo,
                activePage: 'dashboard',
                title: 'Dashboard'
            });
        });
    });
});

// SQL (admin)
app.get('/sql', requireAdmin, (req, res) => {
    renderWithLayout(res, 'sql', { user: req.session.user, activePage: 'sql', title: 'SQL' });
});
app.post('/sql', requireAdmin, (req, res) => {
    const query = req.body.query;
    db.all(query, [], (err, rows) => {
        renderWithLayout(res, 'sql', {
            user: req.session.user,
            query,
            result: err ? undefined : rows,
            error: err ? err.message : undefined,
            activePage: 'sql',
            title: 'SQL'
        });
    });
});

app.get('/sql/tables', requireAdmin, (req, res) => {
    db.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name", [], (err, tables) => {
        if (err) return res.json({ error: err.message });
        let result = {};
        let done = 0;
        if (!tables.length) return res.json({});
        tables.forEach(t => {
            db.all(`PRAGMA table_info(${t.name})`, [], (err2, columns) => {
                result[t.name] = columns.map(c => ({
                    name: c.name,
                    type: c.type
                }));
                done++;
                if (done === tables.length) res.json(result);
            });
        });
    });
});

// Hakkında
app.get('/information', (req, res) => {
    renderWithLayout(res, 'information', { user: req.session.user, activePage: 'information', title: 'Hakkında' });
});

// Dosyalar ana sayfası (sadece giriş yapan kullanıcı)
app.get('/files', requireLogin, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;
    const userId = req.session.user.id;

    db.all('SELECT * FROM FILES WHERE USERID=? AND ACTIVE=1 ORDER BY ID DESC LIMIT ? OFFSET ?', [userId, limit, offset], (err, activeFiles) => {
        db.all('SELECT * FROM FILES WHERE USERID=? AND ACTIVE=0 ORDER BY ID DESC', [userId], (err2, deletedFiles) => {
            db.get('SELECT COUNT(*) as total FROM FILES WHERE USERID=? AND ACTIVE=1', [userId], (err3, row) => {
                const totalPages = Math.ceil((row?.total || 0) / limit);

                // Sadece adminler için tüm dosyaları çek
                if (req.session.user.isAdmin) {
                    db.all(`
                        SELECT FILES.*, USERS.NAME || ' ' || USERS.SURNAME AS ownerName
                        FROM FILES
                        LEFT JOIN USERS ON FILES.USERID = USERS.ID
                        WHERE FILES.ACTIVE=1
                        ORDER BY FILES.ID DESC
                    `, (err4, allFiles) => {
                        renderWithLayout(res, 'files', {
                            user: req.session.user,
                            activeFiles,
                            deletedFiles,
                            allFiles,
                            page,
                            totalPages,
                            title: 'Dosyalarım',
                            error: req.query.error,
                            activePage: 'files'
                        });
                    });
                } else {
                    renderWithLayout(res, 'files', {
                        user: req.session.user,
                        activeFiles,
                        deletedFiles,
                        allFiles: [],
                        page,
                        totalPages,
                        title: 'Dosyalarım',
                        error: req.query.error,
                        activePage: 'files'
                    });
                }
            });
        });
    });
});

// Dosya yükleme
app.post('/files/upload', requireLogin, (req, res, next) => {
    filesUpload.single('file')(req, res, function (err) {
        if (err) {
            return res.redirect('/files?error=Sadece%20resim%20ve%20sıkıştırılmış%20dosyalar%20yüklenebilir!');
        }
        next();
    });
}, (req, res) => {
    const { filename, locked } = req.body;
    const userId = req.session.user.id;
    if (!filename || typeof locked === 'undefined' || !req.file) {
        return res.redirect('/files?error=Alanlar%20eksik');
    }
    db.run(
        'INSERT INTO FILES (USERID, FILENAME, ORIGINALNAME, LOCKED, ACTIVE) VALUES (?, ?, ?, ?, 1)',
        [userId, '', filename.trim(), locked === '1' ? 1 : 0],
        function (err) {
            if (err) return res.redirect('/files?error=Veritabanı%20hatası');
            const newFileName = this.lastID + path.extname(req.file.originalname);
            const oldPath = req.file.path;
            const newPath = path.join(__dirname, 'public', 'files', newFileName);

            fs.rename(oldPath, newPath, (err2) => {
                if (err2) {
                    db.run('DELETE FROM FILES WHERE ID=?', [this.lastID], () => {});
                    return res.redirect('/files?error=Dosya%20taşınamadı');
                }
                db.run('UPDATE FILES SET FILENAME=? WHERE ID=?', [newFileName, this.lastID], (err3) => {
                    if (err3) {
                        db.run('DELETE FROM FILES WHERE ID=?', [this.lastID], () => {});
                        return res.redirect('/files?error=Veritabanı%20güncellenemedi');
                    }
                    res.redirect('/files');
                });
            });
        }
    );
});

// Dosya kalıcı sil
app.post('/files/permanent-delete/:id', requireLogin, (req, res) => {
    db.get('SELECT FILENAME FROM FILES WHERE ID=? AND USERID=?', [req.params.id, req.session.user.id], (err, row) => {
        if (row) {
            fs.unlink(path.join(__dirname, 'public', 'files', row.FILENAME), () => {
                db.run('DELETE FROM FILES WHERE ID=? AND USERID=?', [req.params.id, req.session.user.id], () => {
                    res.redirect('/files');
                });
            });
        } else {
            res.redirect('/files');
        }
    });
});

// Dosya indir (herkes veya sadece sahibi)
app.get('/files/download/:id', (req, res) => {
    db.get('SELECT * FROM FILES WHERE ID=?', [req.params.id], (err, file) => {
        if (!file) return res.status(404).render('error', { user: req.session.user, error: 'Dosya bulunamadı.', title: 'Hata', layout: false });
        if (file.LOCKED && (!req.session.user || req.session.user.id !== file.USERID)) {
            return res.status(403).render('error', { user: req.session.user, error: 'Bu dosya kilitli.', title: 'Hata', layout: false });
        }
        res.download(path.join(__dirname, 'public', 'files', file.FILENAME), file.ORIGINALNAME);
    });
});

// Dosya görüntüle (herkes, ama kilitli ise sadece sahibi)
app.get('/files/view/:id', (req, res) => {
    db.get('SELECT * FROM FILES WHERE ID=?', [req.params.id], (err, file) => {
        if (!file || file.ACTIVE === 0) return res.status(404).render('error', { user: req.session.user, error: 'Dosya bulunamadı.', title: 'Hata', layout: false });
        if (file.LOCKED && (!req.session.user || req.session.user.id !== file.USERID)) {
            return res.status(403).render('error', { user: req.session.user, error: 'Bu dosya kilitli ve sadece sahibi görüntüleyebilir.', title: 'Hata', layout: false });
        }
        res.render('filesview', { file, layout: false });
    });
});

// Dosya sil (aktif => silinen)
app.post('/files/delete/:id', requireLogin, (req, res) => {
    db.run('UPDATE FILES SET ACTIVE=0 WHERE ID=? AND USERID=?', [req.params.id, req.session.user.id], () => {
        res.redirect('/files');
    });
});

// Dosya aktif et (silinenden geri al)
app.post('/files/activate/:id', requireLogin, (req, res) => {
    db.run('UPDATE FILES SET ACTIVE=1 WHERE ID=? AND USERID=?', [req.params.id, req.session.user.id], () => {
        res.redirect('/files');
    });
});

// Dosya kilitle/aç
app.post('/files/toggle-lock/:id', requireLogin, (req, res) => {
    db.get('SELECT LOCKED FROM FILES WHERE ID=? AND USERID=?', [req.params.id, req.session.user.id], (err, row) => {
        if (row) {
            db.run('UPDATE FILES SET LOCKED=? WHERE ID=?', [row.LOCKED ? 0 : 1, req.params.id], () => {
                res.redirect('/files');
            });
        } else {
            res.redirect('/files');
        }
    });
});

// Dosya düzenle (modal ile)
app.post('/files/edit/:id', requireLogin, (req, res) => {
    const { filename, locked } = req.body;
    db.run('UPDATE FILES SET ORIGINALNAME=?, LOCKED=? WHERE ID=? AND USERID=?', [filename, locked === '1' ? 1 : 0, req.params.id, req.session.user.id], () => {
        res.redirect('/files');
    });
});

// Çıkış
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        res.redirect('/');
    });
});

// Error (layout kullanılmaz)
app.get('/error', (req, res) => {
    res.render('error', { layout: false });
});

app.listen(PORT, () => {
    console.log(`WebReport çalışıyor: http://localhost:${PORT}`);
});