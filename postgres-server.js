const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set');
  process.exit(1);
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000
});

async function initDB() {
  let retries = 5;
  while (retries > 0) {
    try {
      console.log('🔄 Connecting to database...');
      await db.query('SELECT NOW()');
      
      await db.query(`CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255)
      )`);
      
      await db.query(`CREATE TABLE IF NOT EXISTS certificates (
        id SERIAL PRIMARY KEY,
        program_name VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        certificate_path TEXT NOT NULL,
        certificate_id VARCHAR(36) UNIQUE,
        verification_code VARCHAR(255),
        uploaded_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (program_name, email)
      )`);
      
      await db.query(`CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        verified BOOLEAN DEFAULT FALSE
      )`);
      
      await db.query(`CREATE TABLE IF NOT EXISTS programs (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        link VARCHAR(500),
        dates VARCHAR(255),
        created_by VARCHAR(255),
        expiry_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (title, dates)
      )`);
      
      await db.query(`INSERT INTO admins (username, password, email) VALUES ('admin', 'admin123', 'admin@example.com') ON CONFLICT DO NOTHING`);
      
      console.log('✅ PostgreSQL database initialized');
      return;
    } catch (error) {
      console.error(`❌ Database connection failed (${retries} retries left):`, error.message);
      retries--;
      if (retries === 0) {
        console.error('💀 Failed to connect to database after all retries');
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}

initDB();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mnabhishek99@gmail.com',
    pass: 'bummxatjzrqkdktd'
  }
});

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024, files: 200 }
});

let currentAdminSession = null;

app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const result = await db.query('SELECT * FROM admins WHERE username = $1 AND password = $2', [username, password]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const admin = result.rows[0];
    currentAdminSession = {
      id: admin.id,
      username: admin.username,
      role: 'admin',
      email: admin.email
    };
    
    res.json({ 
      message: 'Login successful', 
      role: 'admin',
      username: admin.username
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/programs', async (req, res) => {
  try {
    const result = await db.query('SELECT id, title, link, dates, expiry_date FROM programs ORDER BY title');
    
    if (result.rows.length === 0) {
      const certResult = await db.query('SELECT DISTINCT program_name as title FROM certificates ORDER BY program_name');
      return res.json(certResult.rows.map(row => ({ title: row.title, link: '', dates: '' })));
    }
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/request-certificate', async (req, res) => {
  const { programName, name, email } = req.body;
  
  try {
    const result = await db.query('SELECT * FROM certificates WHERE program_name = $1 AND email = $2 AND name = $3', 
      [programName, email.toLowerCase(), name]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    await db.query('INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3)',
      [email.toLowerCase(), otp, expiresAt]);
    
    const mailOptions = {
      from: 'mnabhishek99@gmail.com',
      to: email,
      subject: 'Your Certificate Download Code',
      html: `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc; padding: 40px 20px;">
          <div style="background: white; border-radius: 16px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 32px;">
              <h1 style="color: #1f2937; font-size: 28px; margin: 0; font-weight: 600;">Certificate Download</h1>
            </div>
            
            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 32px;">
              <p style="color: #374151; font-size: 16px; margin: 0 0 16px;">Your verification code is:</p>
              <div style="background: white; border-radius: 8px; padding: 16px; display: inline-block; border: 2px solid #667eea;">
                <span style="color: #667eea; font-size: 32px; font-weight: 700; letter-spacing: 4px;">${otp}</span>
              </div>
            </div>
            
            <div style="text-align: center; color: #6b7280; font-size: 14px;">
              <p style="margin: 0 0 8px;">This code expires in <strong>10 minutes</strong></p>
              <p style="margin: 0;">Keep this code secure and don't share it with anyone</p>
            </div>
          </div>
        </div>
      `
    };
    
    transporter.sendMail(mailOptions)
      .then(() => {
        res.json({ message: 'OTP sent to your email' });
      })
      .catch(() => {
        res.json({ message: 'OTP: ' + otp, otp });
      });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  
  try {
    const otpResult = await db.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW() AND verified = FALSE',
      [email.toLowerCase(), otp]);
    
    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    
    await db.query('UPDATE otps SET verified = TRUE WHERE id = $1', [otpResult.rows[0].id]);
    
    const certResult = await db.query('SELECT * FROM certificates WHERE email = $1', [email.toLowerCase()]);
    
    if (certResult.rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const cert = certResult.rows[0];
    
    res.json({ 
      success: true, 
      message: 'OTP verified successfully',
      downloadUrl: `/api/download-certificate/${cert.id}`,
      certificateName: cert.name
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/download-certificate/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await db.query('SELECT * FROM certificates WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const cert = result.rows[0];
    
    if (!fsSync.existsSync(cert.certificate_path)) {
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    const filename = `${cert.name} - certificate.pdf`;
    res.download(path.resolve(cert.certificate_path), filename);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

function startServer(port) {
  const server = app.listen(port, () => {
    console.log(`✅ PostgreSQL server running on http://localhost:${port}`);
  });
  
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} busy, trying ${port + 1}...`);
      startServer(port + 1);
    }
  });
}

startServer(PORT);