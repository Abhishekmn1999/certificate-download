const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

// Generate simple UUID without external library
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// MySQL connection
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'certificates_db',
  waitForConnections: true,
  connectionLimit: 10
});

// Initialize database
async function initDB() {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS certificates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      program_name VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      certificate_path TEXT NOT NULL,
      certificate_id VARCHAR(36) UNIQUE,
      verification_code VARCHAR(255),
      uploaded_by VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_cert (program_name, email)
    )`);
    
    // Add new columns to existing certificates
    try {
      await db.execute(`ALTER TABLE certificates ADD COLUMN certificate_id VARCHAR(36) UNIQUE`);
      await db.execute(`ALTER TABLE certificates ADD COLUMN verification_code VARCHAR(255)`);
      await db.execute(`ALTER TABLE certificates ADD COLUMN uploaded_by VARCHAR(255)`);
    } catch (e) {}
    
    await db.execute(`CREATE TABLE IF NOT EXISTS otps (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      otp VARCHAR(6) NOT NULL,
      expires_at DATETIME NOT NULL,
      verified BOOLEAN DEFAULT FALSE
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS admin_sessions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      session_token VARCHAR(255) NOT NULL,
      expires_at DATETIME NOT NULL
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS programs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      link VARCHAR(500),
      dates VARCHAR(255),
      created_by VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_program (title, dates)
    )`);
    
    // Add created_by column to existing programs
    try {
      await db.execute(`ALTER TABLE programs ADD COLUMN created_by VARCHAR(255)`);
    } catch (e) {
      // Column already exists
    }
    
    // Add expiry_date column if it doesn't exist
    try {
      await db.execute(`ALTER TABLE programs ADD COLUMN expiry_date DATETIME`);
    } catch (e) {
      // Column already exists
    }
    
    // Download history table
    await db.execute(`CREATE TABLE IF NOT EXISTS download_history (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      program_name VARCHAR(255) NOT NULL,
      certificate_id INT,
      format VARCHAR(10) DEFAULT 'pdf',
      ip_address VARCHAR(45),
      downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
    )`);
    
    // Admin users table
    await db.execute(`CREATE TABLE IF NOT EXISTS admin_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('super_admin', 'admin', 'viewer') DEFAULT 'admin',
      created_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Add created_by column to existing admin_users table
    try {
      await db.execute(`ALTER TABLE admin_users ADD COLUMN created_by INT`);
    } catch (e) {}
    
    // Activity log table
    await db.execute(`CREATE TABLE IF NOT EXISTS activity_log (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      username VARCHAR(255),
      action VARCHAR(255) NOT NULL,
      details TEXT,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Create super admin if not exists
    try {
      await db.execute(`INSERT INTO admin_users (username, password, email, role) VALUES ('superadmin', 'super123', 'super@admin.com', 'super_admin')`);
      console.log('✅ Super Admin created: superadmin/super123');
    } catch (e) {}
    

    
    // Insert admin user with email
    try {
      await db.execute(`ALTER TABLE admins ADD COLUMN email VARCHAR(255)`);
    } catch (e) {}
    
    try {
      await db.execute(`INSERT INTO admins (username, password, email) VALUES ('admin', 'admin123', 'admin@example.com')`);
      console.log('✅ Admin user created');
    } catch (e) {
      console.log('ℹ️ Admin user already exists');
    }
    
    console.log('✅ MySQL database initialized');
  } catch (error) {
    console.error('❌ Database error:', error);
  }
}

initDB();

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mnabhishek99@gmail.com',
    pass: 'bummxatjzrqkdktd'
  }
});



// Multer setup
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024, files: 200 }
});

// Current session storage
let currentAdminSession = null;

// Admin login
app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Check both old admins table and new admin_users table
    let admin = null;
    
    try {
      const [newRows] = await db.execute('SELECT * FROM admin_users WHERE username = ? AND password = ?', [username, password]);
      if (newRows.length > 0) admin = newRows[0];
    } catch (e) {}
    
    if (!admin) {
      const [oldRows] = await db.execute('SELECT * FROM admins WHERE username = ? AND password = ?', [username, password]);
      if (oldRows.length > 0) {
        admin = { ...oldRows[0], role: 'admin' }; // Default role for old admin
      }
    }
    
    if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
    
    // Store session
    currentAdminSession = {
      id: admin.id,
      username: admin.username,
      role: admin.role || 'admin',
      email: admin.email
    };
    
    // Log activity
    await logActivity(admin.id, admin.username, 'LOGIN', `Admin logged in`, req.ip);
    
    res.json({ 
      message: 'Login successful', 
      role: admin.role || 'admin',
      username: admin.username
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Activity logging function
async function logActivity(userId, username, action, details, ip) {
  try {
    await db.execute('INSERT INTO activity_log (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
      [userId, username, action, details, ip]);
  } catch (e) {
    console.log('Activity log failed:', e.message);
  }
}

// Role check middleware
function checkRole(allowedRoles) {
  return (req, res, next) => {
    if (!currentAdminSession) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (!allowedRoles.includes(currentAdminSession.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    req.admin = currentAdminSession;
    next();
  };
}

// Admin OTP verification
app.post('/api/admin-verify-otp', async (req, res) => {
  const { otp } = req.body;
  
  try {
    const [otpRows] = await db.execute('SELECT * FROM otps WHERE otp = ? AND expires_at > NOW() AND verified = FALSE', [otp]);
    if (otpRows.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });
    
    await db.execute('UPDATE otps SET verified = TRUE WHERE id = ?', [otpRows[0].id]);
    res.json({ message: 'Admin login successful' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Upload certificates
app.post('/api/upload-certificates', upload.fields([
  { name: 'csvFile', maxCount: 1 },
  { name: 'certificates', maxCount: 200 }
]), async (req, res) => {
  try {
    const { programName } = req.body;
    
    if (!programName || !req.files?.csvFile || !req.files?.certificates) {
      return res.status(400).json({ error: 'Missing required files' });
    }

    const participants = [];
    const csvData = await fs.readFile(req.files.csvFile[0].path, 'utf8');
    const lines = csvData.split('\n').slice(1);
    
    for (const line of lines) {
      const [name, email] = line.split(',').map(s => s.trim());
      if (name && email) {
        participants.push({ name, email: email.toLowerCase() });
      }
    }

    const certificates = req.files.certificates;
    let uploaded = 0;

    for (const participant of participants) {
      const nameToMatch = participant.name.toLowerCase().replace(/\s+/g, ' ').trim();
      const cert = certificates.find(c => {
        const filename = c.originalname.toLowerCase();
        return filename.includes(nameToMatch) || 
               filename.includes(nameToMatch.replace(/\s+/g, '')) ||
               filename.includes(nameToMatch.replace(/\s+/g, '-'));
      });
      
      if (cert) {
        try {
          const certificateId = generateUUID();
          const verificationCode = Math.random().toString(36).substring(2, 15);
          
          await db.execute('INSERT INTO certificates (program_name, name, email, certificate_path, certificate_id, verification_code) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE certificate_path = VALUES(certificate_path), certificate_id = VALUES(certificate_id), verification_code = VALUES(verification_code)',
            [programName, participant.name, participant.email, cert.path, certificateId, verificationCode]);
          uploaded++;
        } catch (err) {
          console.error('Insert error:', err);
        }
      }
    }

    await fs.unlink(req.files.csvFile[0].path);
    res.json({ message: `${uploaded} certificates uploaded successfully` });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Cache for programs
let programsCache = null;
let cacheTime = 0;

// Get programs with details
app.get('/api/programs', async (req, res) => {
  try {
    // Skip cache if cache buster is present
    const skipCache = req.query.t;
    
    // Return cache if less than 5 minutes old and no cache buster
    if (programsCache && (Date.now() - cacheTime) < 300000 && !skipCache) {
      return res.json(programsCache);
    }
    
    // Try programs table first
    let [rows] = await db.execute('SELECT id, title, link, dates, expiry_date, created_by FROM programs ORDER BY title');
    
    // If no programs in table, use certificates
    if (rows.length === 0) {
      [rows] = await db.execute('SELECT DISTINCT program_name as title FROM certificates ORDER BY program_name');
      rows = rows.map(row => ({ title: row.title, link: '', dates: '' }));
    }
    
    // Cache and return
    programsCache = rows;
    cacheTime = Date.now();
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Request certificate
app.post('/api/request-certificate', async (req, res) => {
  const { programName, name, email } = req.body;
  
  try {
    const [rows] = await db.execute('SELECT * FROM certificates WHERE program_name = ? AND email = ? AND name = ?', 
      [programName, email.toLowerCase(), name]);
    if (rows.length === 0) return res.status(404).json({ error: 'Certificate not found' });
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    await db.execute('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
      [email.toLowerCase(), otp, expiresAt]);
    
    // Send OTP email
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
          
          <div style="text-align: center; margin-top: 24px; color: #9ca3af; font-size: 12px;">
            <p style="margin: 0;">Certificate Download System</p>
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

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  
  try {
    const [otpRows] = await db.execute('SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW() AND verified = FALSE',
      [email.toLowerCase(), otp]);
    if (otpRows.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });
    
    await db.execute('UPDATE otps SET verified = TRUE WHERE id = ?', [otpRows[0].id]);
    
    const [certRows] = await db.execute('SELECT * FROM certificates WHERE email = ?', [email.toLowerCase()]);
    if (certRows.length === 0) return res.status(404).json({ error: 'Certificate not found' });
    
    const cert = certRows[0];
    
    // Check if file exists
    if (!fsSync.existsSync(cert.certificate_path)) {
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    // Return success with download URL
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

// Download certificate endpoint
app.get('/api/download-certificate/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const [rows] = await db.execute('SELECT * FROM certificates WHERE id = ?', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Certificate not found' });
    
    const cert = rows[0];
    
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

// Admin analytics
app.get('/api/admin/analytics', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT program_name, COUNT(*) as total_certificates FROM certificates GROUP BY program_name');
    res.json(rows.map(row => ({ ...row, recent_uploads: 0 })));
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Search certificates
app.get('/api/admin/search', async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  
  try {
    const [rows] = await db.execute('SELECT * FROM certificates WHERE name LIKE ? OR email LIKE ? LIMIT 50', [`%${q}%`, `%${q}%`]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Delete program (POST for better handling of special characters)
app.post('/api/admin/delete-program', async (req, res) => {
  const { programName } = req.body;
  try {
    console.log('Deleting program and all related data:', programName);
    
    // Delete certificates first
    const [certResult] = await db.execute('DELETE FROM certificates WHERE program_name = ?', [programName]);
    console.log('Deleted certificates:', certResult.affectedRows);
    
    // Delete program
    const [progResult] = await db.execute('DELETE FROM programs WHERE title = ?', [programName]);
    console.log('Deleted program:', progResult.affectedRows);
    
    if (progResult.affectedRows === 0 && certResult.affectedRows === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    
    // Force clear cache
    programsCache = null;
    cacheTime = 0;
    
    const totalDeleted = progResult.affectedRows + certResult.affectedRows;
    res.json({ message: `Deleted program and ${certResult.affectedRows} certificates` });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: `Delete failed: ${error.message}` });
  }
});

// Keep old DELETE endpoint for compatibility
app.delete('/api/admin/program/:name', async (req, res) => {
  const { name } = req.params;
  try {
    console.log('Deleting program and all related data:', name);
    
    // Delete certificates first
    const [certResult] = await db.execute('DELETE FROM certificates WHERE program_name = ?', [name]);
    console.log('Deleted certificates:', certResult.affectedRows);
    
    // Delete program
    const [progResult] = await db.execute('DELETE FROM programs WHERE title = ?', [name]);
    console.log('Deleted program:', progResult.affectedRows);
    
    if (progResult.affectedRows === 0 && certResult.affectedRows === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    
    // Force clear cache
    programsCache = null;
    cacheTime = 0;
    
    res.json({ message: `Deleted program and ${certResult.affectedRows} certificates` });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: `Delete failed: ${error.message}` });
  }
});

// Export program
app.get('/api/admin/export/:program', async (req, res) => {
  const { program } = req.params;
  try {
    const [rows] = await db.execute('SELECT name, email FROM certificates WHERE program_name = ?', [program]);
    const csv = 'name,email\n' + rows.map(r => `"${r.name}","${r.email}"`).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${program}.csv"`);
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: 'Export failed' });
  }
});

// Get program details
app.get('/api/program-details/:program', async (req, res) => {
  const { program } = req.params;
  try {
    const [rows] = await db.execute('SELECT title, link, dates FROM programs WHERE title = ?', [program]);
    
    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.json({ title: program, link: '', dates: '' });
    }
  } catch (error) {
    res.json({ title: program, link: '', dates: '' });
  }
});

// Upload programs CSV
app.post('/api/admin/upload-programs-csv', upload.single('programsCsv'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No CSV file uploaded' });
    }

    const csvData = await fs.readFile(req.file.path, 'utf8');
    const lines = csvData.split('\n').slice(1); // Skip header
    
    let added = 0;
    let duplicates = [];
    
    for (const line of lines) {
      if (line.trim()) {
        // Handle CSV with quoted fields
        const parts = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
          const char = line[i];
          if (char === '"') {
            inQuotes = !inQuotes;
          } else if (char === ',' && !inQuotes) {
            parts.push(current.trim());
            current = '';
          } else {
            current += char;
          }
        }
        parts.push(current.trim());
        
        const [title, dates, link] = parts.map(s => s.replace(/^"|"$/g, ''));
        
        if (title) {
          try {
            // Check for duplicate (same title + dates)
            const [existing] = await db.execute('SELECT id FROM programs WHERE title = ? AND dates = ?', [title, dates || '']);
            
            if (existing.length === 0) {
              await db.execute('INSERT INTO programs (title, link, dates) VALUES (?, ?, ?)', 
                [title, link || '', dates || '']);
              added++;
            } else {
              duplicates.push(title);
            }
          } catch (err) {
            if (err.code === 'ER_DUP_ENTRY') {
              duplicates.push(title);
            } else {
              throw err;
            }
          }
        }
      }
    }
    
    // Cleanup
    await fs.unlink(req.file.path);
    
    // Force clear cache
    programsCache = null;
    cacheTime = 0;
    
    let message = `Added ${added} new programs`;
    if (duplicates.length > 0) {
      message += `. Skipped ${duplicates.length} duplicates: ${duplicates.slice(0, 3).join(', ')}`;
      if (duplicates.length > 3) message += '...';
    }
    
    res.json({ message, added, duplicates: duplicates.length });
  } catch (error) {
    console.error('CSV upload error:', error);
    res.status(500).json({ error: `Upload failed: ${error.message}` });
  }
});

// Add program
app.post('/api/admin/add-program', async (req, res) => {
  const { title, link, dates, expiry } = req.body;
  
  try {
    // Check for duplicate (same title + dates)
    const [existing] = await db.execute('SELECT id FROM programs WHERE title = ? AND dates = ?', [title, dates || '']);
    
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Program with same name and duration already exists' });
    }
    
    // Calculate expiry date if not provided
    let expiryDate = expiry;
    if (!expiryDate && dates) {
      // Try to extract end date from duration string and add 1 year
      const dateMatch = dates.match(/(\d{4})\s*$/);
      if (dateMatch) {
        const endYear = parseInt(dateMatch[1]) + 1;
        expiryDate = `${endYear}-12-31`;
      }
    }
    
    await db.execute('INSERT INTO programs (title, link, dates, expiry_date) VALUES (?, ?, ?, ?)', 
      [title, link || '', dates || '', expiryDate || null]);
    
    // Force clear cache
    programsCache = null;
    cacheTime = 0;
    
    res.json({ message: 'Program added successfully', refresh: true });
  } catch (error) {
    console.error('Add program error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});



// Update program expiry date
app.post('/api/admin/update-expiry', async (req, res) => {
  try {
    const { programId, expiryDate } = req.body;
    
    await db.execute('UPDATE programs SET expiry_date = ? WHERE id = ?', 
      [expiryDate || null, programId]);
    
    // Clear cache
    programsCache = null;
    cacheTime = 0;
    
    res.json({ message: 'Expiry date updated' });
  } catch (error) {
    console.error('Update expiry error:', error);
    res.status(500).json({ error: 'Update failed' });
  }
});





// Admin download certificate
app.get('/api/admin/download/:id', async (req, res) => {
  const { id } = req.params;
  try {
    console.log('Admin downloading certificate ID:', id);
    const [rows] = await db.execute('SELECT * FROM certificates WHERE id = ?', [id]);
    if (rows.length === 0) {
      console.log('Certificate not found for ID:', id);
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const cert = rows[0];
    console.log('Certificate path:', cert.certificate_path);
    
    // Check if file exists
    if (!fsSync.existsSync(cert.certificate_path)) {
      console.log('File not found:', cert.certificate_path);
      return res.status(404).json({ error: 'Certificate file not found' });
    }
    
    const filename = `${cert.name} - certificate.pdf`;
    res.download(path.resolve(cert.certificate_path), filename);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Certificate Preview PDF
app.get('/api/preview-pdf', async (req, res) => {
  const { programName, name, email, otp } = req.query;
  
  try {
    // Verify OTP first
    const [otpRows] = await db.execute('SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW()',
      [email.toLowerCase(), otp]);
    if (otpRows.length === 0) {
      res.setHeader('Content-Type', 'text/html');
      return res.send('<h3>Invalid or expired OTP</h3>');
    }
    
    const [rows] = await db.execute('SELECT * FROM certificates WHERE program_name = ? AND email = ?', 
      [programName, email.toLowerCase()]);
    if (rows.length === 0) {
      res.setHeader('Content-Type', 'text/html');
      return res.send('<h3>Certificate not found</h3>');
    }
    
    const cert = rows[0];
    if (!fsSync.existsSync(cert.certificate_path)) {
      res.setHeader('Content-Type', 'text/html');
      return res.send('<h3>Certificate file not found</h3>');
    }
    
    // Mark OTP as used
    await db.execute('UPDATE otps SET verified = TRUE WHERE id = ?', [otpRows[0].id]);
    
    // Set headers for PDF display
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename="certificate-preview.pdf"');
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(path.resolve(cert.certificate_path));
  } catch (error) {
    console.error('Preview error:', error);
    res.setHeader('Content-Type', 'text/html');
    res.send('<h3>Preview failed</h3>');
  }
});

// Admin Download History
app.get('/api/admin/all-downloads', async (req, res) => {
  try {
    // First check if table exists, if not create it
    try {
      const [rows] = await db.execute(
        'SELECT * FROM download_history ORDER BY downloaded_at DESC LIMIT 100'
      );
      res.json(rows);
    } catch (tableError) {
      // Table doesn't exist, return empty array
      res.json([]);
    }
  } catch (error) {
    console.error('Download history error:', error);
    res.json([]);
  }
});



// User Management (Super Admin Only)
app.post('/api/admin/add-user', checkRole(['super_admin']), async (req, res) => {
  const { username, email, password, role } = req.body;
  
  try {
    // Ensure admin_users table exists
    await db.execute(`CREATE TABLE IF NOT EXISTS admin_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('super_admin', 'admin', 'viewer') DEFAULT 'admin',
      created_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    await db.execute('INSERT INTO admin_users (username, email, password, role) VALUES (?, ?, ?, ?)', 
      [username, email, password, role]);
    
    await logActivity(req.admin.id, req.admin.username, 'CREATE_USER', `Created user: ${username} with role: ${role}`, req.ip);
    
    res.json({ message: 'User added successfully' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      console.error('Add user error:', error);
      res.status(500).json({ error: 'Database error: ' + error.message });
    }
  }
});

// Get current user info
app.get('/api/admin/current-user', (req, res) => {
  if (currentAdminSession) {
    res.json(currentAdminSession);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Activity Log (Super Admin Only)
app.get('/api/admin/activity-log', checkRole(['super_admin']), async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 100');
    res.json(rows);
  } catch (error) {
    res.json([]);
  }
});

// User Contributions (Super Admin Only)
app.get('/api/admin/user-contributions', async (req, res) => {
  try {
    const userStats = {};
    
    // Get programs created by each user
    try {
      const [programs] = await db.execute('SELECT created_by, title FROM programs WHERE created_by IS NOT NULL');
      programs.forEach(prog => {
        if (!userStats[prog.created_by]) {
          userStats[prog.created_by] = { programs: [], certificates: 0, programNames: [] };
        }
        userStats[prog.created_by].programs.push(prog.title);
        userStats[prog.created_by].programNames.push(prog.title);
      });
    } catch (e) {
      console.log('Programs query error:', e.message);
    }
    
    // Get certificates uploaded by each user
    try {
      const [certs] = await db.execute('SELECT uploaded_by, COUNT(*) as count FROM certificates WHERE uploaded_by IS NOT NULL GROUP BY uploaded_by');
      certs.forEach(cert => {
        if (!userStats[cert.uploaded_by]) {
          userStats[cert.uploaded_by] = { programs: [], certificates: 0, programNames: [] };
        }
        userStats[cert.uploaded_by].certificates = cert.count;
      });
    } catch (e) {
      console.log('Certificates query error:', e.message);
    }
    
    res.json(userStats);
  } catch (error) {
    console.error('User contributions error:', error);
    res.json({});
  }
});

// Generate Certificate ID and Verification Code
app.post('/api/admin/generate-cert-ids', checkRole(['super_admin', 'admin']), async (req, res) => {
  try {
    const [certificates] = await db.execute('SELECT id, name, program_name FROM certificates WHERE certificate_id IS NULL OR verification_code IS NULL');
    
    let updated = 0;
    for (const cert of certificates) {
      const certificateId = generateUUID();
      const verificationCode = Math.random().toString(36).substring(2, 15).toUpperCase();
      
      await db.execute('UPDATE certificates SET certificate_id = ?, verification_code = ? WHERE id = ?',
        [certificateId, verificationCode, cert.id]);
      updated++;
    }
    
    await logActivity(req.admin.id, req.admin.username, 'GENERATE_CERT_IDS', `Generated IDs for ${updated} certificates`, req.ip);
    
    res.json({ message: `Generated IDs for ${updated} certificates` });
  } catch (error) {
    console.error('Generate IDs error:', error);
    res.status(500).json({ error: 'Failed to generate certificate IDs' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    // Ensure admin_users table exists
    await db.execute(`CREATE TABLE IF NOT EXISTS admin_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('super_admin', 'admin', 'viewer') DEFAULT 'admin',
      created_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    const [rows] = await db.execute('SELECT id, username, email, role, created_at FROM admin_users ORDER BY created_at DESC');
    
    if (rows.length === 0) {
      // Return default admin user if no users exist
      res.json([{
        id: 1,
        username: 'admin',
        email: 'admin@example.com',
        role: 'super_admin',
        created_at: new Date()
      }]);
    } else {
      res.json(rows);
    }
  } catch (error) {
    console.error('Users error:', error);
    res.json([]);
  }
});

// Reset password endpoint
app.post('/api/admin/reset-password', async (req, res) => {
  const { username, newPassword, resetKey } = req.body;
  
  // Simple reset key for security
  if (resetKey !== 'RESET2024') {
    return res.status(401).json({ error: 'Invalid reset key' });
  }
  
  try {
    // Try admin_users table first
    const [result1] = await db.execute('UPDATE admin_users SET password = ? WHERE username = ?', [newPassword, username]);
    
    // Try old admins table
    const [result2] = await db.execute('UPDATE admins SET password = ? WHERE username = ?', [newPassword, username]);
    
    if (result1.affectedRows > 0 || result2.affectedRows > 0) {
      res.json({ message: `Password reset for ${username}` });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Reset failed' });
  }
});

// Logout endpoint
app.post('/api/admin/logout', async (req, res) => {
  if (currentAdminSession) {
    await logActivity(currentAdminSession.id, currentAdminSession.username, 'LOGOUT', 'Admin logged out', req.ip);
    currentAdminSession = null;
  }
  res.json({ message: 'Logged out successfully' });
});

// Edit user
app.put('/api/admin/edit-user/:id', checkRole(['super_admin']), async (req, res) => {
  const { id } = req.params;
  const { username, email, role } = req.body;
  
  try {
    await db.execute('UPDATE admin_users SET username = ?, email = ?, role = ? WHERE id = ?',
      [username, email, role, id]);
    
    await logActivity(req.admin.id, req.admin.username, 'EDIT_USER', `Edited user: ${username}`, req.ip);
    
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Database error' });
    }
  }
});

app.delete('/api/admin/delete-user/:id', checkRole(['super_admin']), async (req, res) => {
  const { id } = req.params;
  try {
    const [user] = await db.execute('SELECT username FROM admin_users WHERE id = ?', [id]);
    await db.execute('DELETE FROM admin_users WHERE id = ?', [id]);
    
    await logActivity(req.admin.id, req.admin.username, 'DELETE_USER', `Deleted user: ${user[0]?.username}`, req.ip);
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Statistics
app.get('/api/admin/statistics', async (req, res) => {
  try {
    // Get basic stats from certificates table
    const [totalCerts] = await db.execute('SELECT COUNT(*) as count FROM certificates');
    const [totalPrograms] = await db.execute('SELECT COUNT(DISTINCT program_name) as count FROM certificates');
    const [recentCerts] = await db.execute('SELECT COUNT(*) as count FROM certificates WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)');
    
    // Try to get download stats, fallback if table doesn't exist
    let downloadStats = { totalDownloads: 0, activeUsers: 0, popularProgram: 'None', todayDownloads: 0 };
    try {
      const [totalDownloads] = await db.execute('SELECT COUNT(*) as count FROM download_history');
      const [activeUsers] = await db.execute('SELECT COUNT(DISTINCT email) as count FROM download_history WHERE downloaded_at > DATE_SUB(NOW(), INTERVAL 30 DAY)');
      const [popularProgram] = await db.execute('SELECT program_name, COUNT(*) as count FROM download_history GROUP BY program_name ORDER BY count DESC LIMIT 1');
      const [todayDownloads] = await db.execute('SELECT COUNT(*) as count FROM download_history WHERE DATE(downloaded_at) = CURDATE()');
      
      downloadStats = {
        totalDownloads: totalDownloads[0].count,
        activeUsers: activeUsers[0].count,
        popularProgram: popularProgram[0]?.program_name || 'None',
        todayDownloads: todayDownloads[0].count
      };
    } catch (e) {
      console.log('Download history table not found, using basic stats');
    }
    
    res.json({
      ...downloadStats,
      totalCertificates: totalCerts[0].count,
      totalPrograms: totalPrograms[0].count,
      recentCertificates: recentCerts[0].count
    });
  } catch (error) {
    console.error('Statistics error:', error);
    res.json({
      totalDownloads: 0,
      activeUsers: 0,
      popularProgram: 'None',
      todayDownloads: 0,
      totalCertificates: 0,
      totalPrograms: 0,
      recentCertificates: 0
    });
  }
});

// Bulk Download (simplified)
app.post('/api/admin/bulk-download', async (req, res) => {
  const { certificateIds } = req.body;
  
  try {
    const [certificates] = await db.execute(
      `SELECT * FROM certificates WHERE id IN (${certificateIds.map(() => '?').join(',')})`, 
      certificateIds
    );
    
    // For now, just return the first certificate
    // TODO: Implement proper ZIP creation
    if (certificates.length > 0 && fsSync.existsSync(certificates[0].certificate_path)) {
      res.download(path.resolve(certificates[0].certificate_path), 'certificate.pdf');
    } else {
      res.status(404).json({ error: 'No certificates found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Bulk download failed' });
  }
});

// Get certificates by program
app.get('/api/certificates/:program', async (req, res) => {
  const { program } = req.params;
  try {
    const [rows] = await db.execute('SELECT * FROM certificates WHERE program_name = ? ORDER BY name', [program]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Get admin programs endpoint
app.get('/api/admin/programs', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM programs ORDER BY title');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});



// Certificate Verification
app.post('/api/verify-certificate', async (req, res) => {
  const { code } = req.body;
  
  try {
    const [rows] = await db.execute(
      'SELECT * FROM certificates WHERE certificate_id = ? OR verification_code = ?', 
      [code, code]
    );
    
    if (rows.length > 0) {
      const cert = rows[0];
      res.json({
        valid: true,
        name: cert.name,
        program_name: cert.program_name,
        created_at: cert.created_at,
        certificate_id: cert.certificate_id
      });
    } else {
      res.json({ valid: false });
    }
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});



// Start server
function startServer(port) {
  const server = app.listen(port, () => {
    console.log(`✅ MySQL server running on http://localhost:${port}`);
  });
  
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} busy, trying ${port + 1}...`);
      startServer(port + 1);
    }
  });
}

startServer(PORT);