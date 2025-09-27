const express = require('express');
const sqlite3 = require('sqlite3').verbose();
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

const db = new sqlite3.Database('certificates.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'admin'
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_name TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    certificate_path TEXT NOT NULL,
    certificate_id TEXT UNIQUE,
    verification_code TEXT,
    uploaded_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (program_name, email)
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    verified BOOLEAN DEFAULT 0
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    link TEXT,
    dates TEXT,
    created_by TEXT,
    expiry_date DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (title, dates)
  )`);
  
  db.run(`INSERT OR IGNORE INTO admins (username, password, email, role) VALUES ('admin', 'admin123', 'admin@example.com', 'admin')`);
  db.run(`INSERT OR IGNORE INTO admins (username, password, email, role) VALUES ('superadmin', 'super123', 'superadmin@example.com', 'superadmin')`);
  
  console.log('✅ SQLite database initialized');
});

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

app.post('/api/admin-login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM admins WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!row) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    currentAdminSession = {
      id: row.id,
      username: row.username,
      role: row.role || 'admin',
      email: row.email
    };
    
    res.json({ 
      message: 'Login successful', 
      role: row.role || 'admin',
      username: row.username
    });
  });
});

app.get('/api/programs', (req, res) => {
  db.all('SELECT id, title, link, dates, expiry_date FROM programs ORDER BY title', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (rows.length === 0) {
      db.all('SELECT DISTINCT program_name as title FROM certificates ORDER BY program_name', (err, certRows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(certRows.map(row => ({ title: row.title, link: '', dates: '' })));
      });
    } else {
      res.json(rows);
    }
  });
});

app.get('/api/admin/programs', (req, res) => {
  db.all('SELECT * FROM programs ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/admin/programs', (req, res) => {
  const { title, link, dates, expiry_date } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Program title is required' });
  }
  
  const createdBy = currentAdminSession ? currentAdminSession.username : 'admin';
  
  db.run('INSERT INTO programs (title, link, dates, created_by, expiry_date) VALUES (?, ?, ?, ?, ?)',
    [title, link || '', dates || '', createdBy, expiry_date || null], function(err) {
    
    if (err) {
      console.error('Program insert error:', err);
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Program with this title and dates already exists' });
      }
      return res.status(500).json({ error: 'Failed to add program' });
    }
    
    res.json({ message: 'Program added successfully', id: this.lastID });
  });
});

app.delete('/api/admin/programs/:id', (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM programs WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete program' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    
    res.json({ message: 'Program deleted successfully' });
  });
});

app.put('/api/admin/programs/:id', (req, res) => {
  const { id } = req.params;
  const { expiry_date } = req.body;
  
  db.run('UPDATE programs SET expiry_date = ? WHERE id = ?', [expiry_date, id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to update program' });
    }
    
    res.json({ message: 'Program updated successfully' });
  });
});

app.get('/api/admin/stats', (req, res) => {
  db.get('SELECT COUNT(*) as totalPrograms FROM programs', (err, programCount) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    
    db.get('SELECT COUNT(*) as totalCertificates FROM certificates', (err, certCount) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      
      res.json({
        totalPrograms: programCount.totalPrograms,
        totalCertificates: certCount.totalCertificates
      });
    });
  });
});

app.get('/api/admin/certificates', (req, res) => {
  const { search } = req.query;
  let query = 'SELECT * FROM certificates ORDER BY created_at DESC';
  let params = [];
  
  if (search) {
    query = 'SELECT * FROM certificates WHERE name LIKE ? OR email LIKE ? OR program_name LIKE ? ORDER BY created_at DESC';
    params = [`%${search}%`, `%${search}%`, `%${search}%`];
  }
  
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.delete('/api/admin/certificates/:id', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT certificate_path FROM certificates WHERE id = ?', [id], (err, row) => {
    if (err || !row) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    db.run('DELETE FROM certificates WHERE id = ?', [id], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to delete certificate' });
      }
      
      if (fsSync.existsSync(row.certificate_path)) {
        fsSync.unlinkSync(row.certificate_path);
      }
      
      res.json({ message: 'Certificate deleted successfully' });
    });
  });
});

app.get('/api/admin/users', (req, res) => {
  db.all('SELECT id, username, email, role FROM admins', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/admin/users', (req, res) => {
  const { username, password, email, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  db.run('INSERT INTO admins (username, password, email, role) VALUES (?, ?, ?, ?)',
    [username, password, email || '', role || 'admin'], function(err) {
    
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Failed to create user' });
    }
    
    res.json({ message: 'User created successfully', id: this.lastID });
  });
});

app.delete('/api/admin/users/:id', (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM admins WHERE id = ?', [id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete user' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully' });
  });
});

app.post('/api/request-certificate', (req, res) => {
  const { programName, name, email } = req.body;
  
  db.get('SELECT * FROM certificates WHERE program_name = ? AND email = ? AND name = ?', 
    [programName, email.toLowerCase(), name], (err, row) => {
    
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!row) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    
    db.run('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
      [email.toLowerCase(), otp, expiresAt], (err) => {
      
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
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
    });
  });
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  
  db.get('SELECT * FROM otps WHERE email = ? AND otp = ? AND datetime(expires_at) > datetime("now") AND verified = 0',
    [email.toLowerCase(), otp], (err, otpRow) => {
    
    if (err) {
      console.error('Verify OTP error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!otpRow) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    
    db.run('UPDATE otps SET verified = 1 WHERE id = ?', [otpRow.id], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      db.get('SELECT * FROM certificates WHERE email = ?', [email.toLowerCase()], (err, cert) => {
        if (err) {
          console.error('Certificate lookup error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (!cert) {
          return res.status(404).json({ error: 'Certificate not found' });
        }
        
        res.json({ 
          success: true, 
          message: 'OTP verified successfully',
          downloadUrl: `/api/download-certificate/${cert.id}`,
          certificateName: cert.name
        });
      });
    });
  });
});

app.get('/api/download-certificate/:id', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM certificates WHERE id = ?', [id], (err, cert) => {
    if (err) {
      console.error('Download error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!cert) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    if (!fsSync.existsSync(cert.certificate_path)) {
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    const filename = `${cert.name} - certificate.pdf`;
    res.download(path.resolve(cert.certificate_path), filename);
  });
});

function startServer(port) {
  const server = app.listen(port, () => {
    console.log(`✅ SQLite server running on http://localhost:${port}`);
  });
  
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} busy, trying ${port + 1}...`);
      startServer(port + 1);
    }
  });
}

startServer(PORT);