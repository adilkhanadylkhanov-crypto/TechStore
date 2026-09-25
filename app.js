const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super_secret_key_2026';

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname))
});
const upload = multer({ storage });

if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

app.use(express.json());
app.use(cors());
app.use(express.static(__dirname));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const verificationCodes = {};
const db = new sqlite3.Database('./shop.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    image TEXT,
    description TEXT,
    full_info TEXT,
    colors TEXT,
    storage_options TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    items TEXT,
    total_price REAL,
    customer_first_name TEXT,
    customer_last_name TEXT,
    phone TEXT,
    country TEXT,
    city TEXT,
    address TEXT,
    postal_code TEXT,
    payment_method TEXT DEFAULT 'Банковская карта',
    card_last4 TEXT,
    status TEXT DEFAULT 'Оплачен',
    delivery_days INTEGER DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Обновленный администратор с твоими данными
  const adminHash = bcrypt.hashSync('32525426Albina', 10);
  db.run(`INSERT OR REPLACE INTO users (id, login, password, role) VALUES (1, '+77064064916', ?, 'admin')`, [adminHash]);
});

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Авторизуйтесь в системе' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Сессия истекла' });
  }
}

app.post('/api/upload', authenticate, upload.array('images', 10), (req, res) => {
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Файлы не загружены' });
  const fileUrls = req.files.map(file => `/uploads/${file.filename}`);
  res.json({ imageUrls: fileUrls });
});

app.post('/api/send-code', (req, res) => {
  const { login } = req.body;
  if (!login) return res.status(400).json({ error: 'Укажите логин/телефон' });

  db.get(`SELECT id FROM users WHERE login = ?`, [login], (err, user) => {
    if (user) return res.status(400).json({ error: 'Пользователь уже существует' });
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    verificationCodes[login] = { code };
    console.log(`\n📩 СМС-КОД ДЛЯ [${login}]: ${code}\n`);
    res.json({ success: true, demoCode: code });
  });
});

app.post('/api/register', (req, res) => {
  const { login, password, code } = req.body;
  const record = verificationCodes[login];
  if (!record || record.code !== code) return res.status(400).json({ error: 'Неверный СМС-код' });

  delete verificationCodes[login];
  const hash = bcrypt.hashSync(password, 10);

  db.run(`INSERT INTO users (login, password, role) VALUES (?, ?, 'user')`, [login, hash], function(err) {
    if (err) return res.status(400).json({ error: 'Ошибка регистрации' });
    const token = jwt.sign({ id: this.lastID, role: 'user', login }, JWT_SECRET);
    res.json({ token, role: 'user', login });
  });
});

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  db.get(`SELECT * FROM users WHERE login = ?`, [login], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }
    const token = jwt.sign({ id: user.id, role: user.role, login: user.login }, JWT_SECRET);
    res.json({ token, role: user.role, login: user.login });
  });
});

app.get('/api/products', (req, res) => {
  db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || []));
});

app.get('/api/products/:id', (req, res) => {
  db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => {
    if (!row) return res.status(404).json({ error: 'Товар не найден' });
    res.json(row);
  });
});

app.post('/api/products', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  const { name, price, image, description, full_info, colors, storage_options } = req.body;
  db.run(
    `INSERT INTO products (name, price, image, description, full_info, colors, storage_options) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [name, price, image || '', description || '', full_info || '', colors || '', storage_options || ''],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, name, price });
    }
  );
});

app.put('/api/products/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  const { name, price, image, description, full_info, colors, storage_options } = req.body;
  db.run(
    `UPDATE products SET name=?, price=?, image=?, description=?, full_info=?, colors=?, storage_options=? WHERE id=?`,
    [name, price, image || '', description || '', full_info || '', colors || '', storage_options || '', req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.delete('/api/products/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  db.run(`DELETE FROM products WHERE id=?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.post('/api/orders', authenticate, (req, res) => {
  const { items, totalPrice, customerFirstName, customerLastName, phone, country, city, address, postalCode, cardNumber } = req.body;
  const cardLast4 = String(cardNumber || '').replace(/\s/g, '').slice(-4);
  const fullAddress = `${country}, г. ${city}, ${address}, Индекс: ${postalCode}`;

  db.run(
    `INSERT INTO orders (
      user_id, items, total_price, customer_first_name, customer_last_name, phone, country, city, address, postal_code, payment_method, card_last4
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Банковская карта', ?)`,
    [req.user.id, JSON.stringify(items), totalPrice, customerFirstName, customerLastName, phone, country, city, fullAddress, postalCode, cardLast4],
    function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка БД: ' + err.message });
      res.json({ orderId: this.lastID });
    }
  );
});

app.get('/api/my-orders', authenticate, (req, res) => {
  db.all(`SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC`, [req.user.id], (err, rows) => res.json(rows || []));
});

app.post('/api/orders/request-cancel/:id', authenticate, (req, res) => {
  db.run(`UPDATE orders SET status = 'Запрошена отмена' WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], function(err) {
    res.json({ success: true });
  });
});

app.post('/api/admin/orders/confirm-cancel/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  db.run(`DELETE FROM orders WHERE id = ?`, [req.params.id], function(err) {
    res.json({ success: true });
  });
});

app.get('/api/admin/orders', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  db.all(`SELECT orders.*, users.login FROM orders JOIN users ON orders.user_id = users.id ORDER BY id DESC`, [], (err, orders) => {
    db.get(`SELECT SUM(total_price) as balance FROM orders WHERE status != 'Отменен'`, [], (err, result) => {
      res.json({ orders: orders || [], balance: result ? result.balance || 0 : 0 });
    });
  });
});

app.post('/api/admin/withdraw', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  const { amount, method, target } = req.body;
  res.json({ success: true, message: `Заявка на вывод ${amount} ₸ методом [${method}] на реквизиты [${target}] сформирована!` });
});

app.post('/api/admin/order/delivery', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  db.run(`UPDATE orders SET delivery_days = ? WHERE id = ?`, [req.body.days, req.body.orderId], () => res.json({ success: true }));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🚀 Сервер запущен: http://localhost:${PORT}\n`);
});