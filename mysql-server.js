const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

// MySQL connection
const dbConfig = process.env.DATABASE_URL || {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'certificate_system',
  ssl: { rejectUnauthorized: false }
};

let db;

async function initDB() {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log('✅ Connected to MySQL database');
    
    // Create tables
    await db.execute(`CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      email VARCHAR(255),
      role VARCHAR(50) DEFAULT 'admin',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS programs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      link VARCHAR(500),
      dates VARCHAR(255),
      created_by VARCHAR(255),
      expiry_date DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_program (title, dates)
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS certificates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      program_name VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL,
      certificate_data LONGBLOB NOT NULL,
      certificate_id VARCHAR(36) UNIQUE,
      verification_code VARCHAR(255),
      uploaded_by VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_cert (program_name, email)
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS otps (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      otp VARCHAR(6) NOT NULL,
      expires_at DATETIME NOT NULL,
      verified BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    await db.execute(`CREATE TABLE IF NOT EXISTS download_history (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      program_name VARCHAR(255) NOT NULL,
      format VARCHAR(10) DEFAULT 'pdf',
      ip_address VARCHAR(45),
      downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Insert default admin users
    await db.execute(`INSERT IGNORE INTO admins (username, password, email, role) VALUES 
      ('admin', 'admin123', 'admin@example.com', 'admin'),
      ('superadmin', 'super123', 'superadmin@example.com', 'super_admin')`);
    
    // Insert default program
    await db.execute(`INSERT IGNORE INTO programs (title, link, dates, created_by) VALUES 
      ('Dynamics and Evolution of RNA Functions', 'https://www.icts.res.in/program/rna2024', '22 September 2025 to 03 October 2025', 'admin')`);
    
    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('❌ Database error:', error);
    process.exit(1);
  }
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mnabhishek99@gmail.com',
    pass: 'bummxatjzrqkdktd'
  }
});

const upload = multer({ dest: 'uploads/' });
let currentAdminSession = null;

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Admin login
app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const [rows] = await db.execute('SELECT * FROM admins WHERE username = ? AND password = ?', [username, password]);
    
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const admin = rows[0];
    currentAdminSession = admin;
    
    res.json({ 
      message: 'Login successful', 
      role: admin.role,
      username: admin.username
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get programs
app.get('/api/programs', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, title, link, dates, expiry_date FROM programs ORDER BY title');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Admin programs
app.get('/api/admin/programs', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM programs ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/programs', async (req, res) => {
  const { title, link, dates, expiry_date } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Program title is required' });
  }
  
  try {
    const createdBy = currentAdminSession ? currentAdminSession.username : 'admin';
    
    await db.execute('INSERT INTO programs (title, link, dates, created_by, expiry_date) VALUES (?, ?, ?, ?, ?)',
      [title, link || '', dates || '', createdBy, expiry_date || null]);
    
    res.json({ message: 'Program added successfully' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Program with this title and dates already exists' });
    }
    res.status(500).json({ error: 'Failed to add program' });
  }
});

app.delete('/api/admin/programs/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const [result] = await db.execute('DELETE FROM programs WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    
    res.json({ message: 'Program deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete program' });
  }
});

// Stats
app.get('/api/admin/stats', async (req, res) => {
  try {
    const [programCount] = await db.execute('SELECT COUNT(*) as count FROM programs');
    const [certCount] = await db.execute('SELECT COUNT(*) as count FROM certificates');
    
    res.json({
      totalPrograms: programCount[0].count,
      totalCertificates: certCount[0].count
    });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Upload certificates
app.post('/api/upload-certificates', upload.fields([{ name: 'csvFile' }, { name: 'certificates' }]), async (req, res) => {
  const programName = req.body.programName;
  const csvFile = req.files?.csvFile?.[0];
  const certificateFiles = req.files?.certificates || [];
  
  if (!programName || !csvFile) {
    return res.status(400).json({ error: 'Program name and CSV file are required' });
  }
  
  try {
    const csvContent = fs.readFileSync(csvFile.path, 'utf8');
    const lines = csvContent.split('\n').filter(line => line.trim());
    
    if (lines.length < 2) {
      return res.status(400).json({ error: 'CSV file must have header and at least one data row' });
    }
    
    let added = 0;
    const uploadedBy = currentAdminSession ? currentAdminSession.username : 'admin';
    
    for (let i = 1; i < lines.length; i++) {
      const [name, email] = lines[i].split(',').map(s => s.trim().replace(/"/g, ''));
      
      if (name && email) {
        try {
          const certFile = certificateFiles.find(file => 
            file.originalname.toLowerCase().includes(name.toLowerCase()) ||
            name.toLowerCase().includes(file.originalname.toLowerCase().replace('.pdf', ''))
          );
          
          let certificateData = null;
          if (certFile) {
            certificateData = fs.readFileSync(certFile.path);
          }
          
          if (certificateData) {
            await db.execute(`INSERT INTO certificates (program_name, name, email, certificate_data, certificate_id, uploaded_by) 
              VALUES (?, ?, ?, ?, ?, ?)`,
              [programName, name, email.toLowerCase(), certificateData, 
               `CERT-${Date.now()}-${i}`, uploadedBy]);
            added++;
          }
        } catch (error) {
          if (error.code !== 'ER_DUP_ENTRY') {
            console.error('Insert error:', error);
          }
        }
      }
    }
    
    certificateFiles.forEach(file => {
      if (fs.existsSync(file.path)) {
        fs.unlinkSync(file.path);
      }
    });
    
    fs.unlinkSync(csvFile.path);
    
    res.json({ 
      message: `Successfully added ${added} certificates for ${programName}`,
      totalCertificates: added
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to process CSV file' });
  }
});

// Certificate request
app.post('/api/request-certificate', async (req, res) => {
  const { programName, name, email } = req.body;
  
  try {
    const [rows] = await db.execute('SELECT * FROM certificates WHERE program_name = ? AND email = ? AND name = ?', 
      [programName, email.toLowerCase(), name]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found. Please check your name and email match exactly as registered.' });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    await db.execute('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
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

// OTP verification
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  
  try {
    const [otpRows] = await db.execute('SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW() AND verified = FALSE',
      [email.toLowerCase(), otp]);
    
    if (otpRows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    
    await db.execute('UPDATE otps SET verified = TRUE WHERE id = ?', [otpRows[0].id]);
    
    const [certRows] = await db.execute('SELECT * FROM certificates WHERE email = ?', [email.toLowerCase()]);
    
    if (certRows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const cert = certRows[0];
    
    // Log download
    await db.execute('INSERT INTO download_history (email, program_name, ip_address) VALUES (?, ?, ?)',
      [email.toLowerCase(), cert.program_name, req.ip]);
    
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

// Admin download certificate
app.get('/api/admin/download/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const [rows] = await db.execute('SELECT name, certificate_data FROM certificates WHERE id = ?', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const cert = rows[0];
    const filename = `${cert.name} - Certificate.pdf`;
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(cert.certificate_data);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Download certificate
app.get('/api/download-certificate/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const [rows] = await db.execute('SELECT name, certificate_data FROM certificates WHERE id = ?', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const cert = rows[0];
    const filename = `${cert.name} - Certificate.pdf`;
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(cert.certificate_data);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Analytics
app.get('/api/admin/analytics', async (req, res) => {
  try {
    const [rows] = await db.execute(`SELECT p.title as program_name, COUNT(c.id) as total_certificates 
      FROM programs p LEFT JOIN certificates c ON p.title = c.program_name 
      GROUP BY p.title ORDER BY p.title`);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Export certificates
app.get('/api/admin/export/:program', async (req, res) => {
  const { program } = req.params;
  
  try {
    const [rows] = await db.execute('SELECT * FROM certificates WHERE program_name = ?', [decodeURIComponent(program)]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No certificates found for this program' });
    }
    
    let csv = 'Name,Email,Program,Created Date\n';
    rows.forEach(cert => {
      csv += `"${cert.name}","${cert.email}","${cert.program_name}","${new Date(cert.created_at).toLocaleDateString()}"\n`;
    });
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${program}-certificates.csv"`);
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: 'Export failed' });
  }
});

// Delete program
app.post('/api/admin/delete-program', async (req, res) => {
  const { programName } = req.body;
  
  try {
    const [certResult] = await db.execute('DELETE FROM certificates WHERE program_name = ?', [programName]);
    const [progResult] = await db.execute('DELETE FROM programs WHERE title = ?', [programName]);
    
    if (progResult.affectedRows === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    
    res.json({ 
      message: `Program deleted successfully. Also removed ${certResult.affectedRows} certificates.` 
    });
  } catch (error) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Users management
app.get('/api/admin/users', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, username, email, role, created_at FROM admins');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/users', async (req, res) => {
  const { username, password, email, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  try {
    await db.execute('INSERT INTO admins (username, password, email, role) VALUES (?, ?, ?, ?)',
      [username, password, email || '', role || 'admin']);
    
    res.json({ message: 'User created successfully' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.delete('/api/admin/users/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const [result] = await db.execute('DELETE FROM admins WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Statistics
app.get('/api/admin/statistics', async (req, res) => {
  try {
    const [downloadCount] = await db.execute('SELECT COUNT(*) as count FROM download_history');
    const [userCount] = await db.execute('SELECT COUNT(*) as count FROM admins');
    const [todayCount] = await db.execute('SELECT COUNT(*) as count FROM download_history WHERE DATE(downloaded_at) = CURDATE()');
    const [popularProgram] = await db.execute(`SELECT program_name, COUNT(*) as downloads 
      FROM download_history GROUP BY program_name ORDER BY downloads DESC LIMIT 1`);
    
    res.json({
      totalDownloads: downloadCount[0].count,
      activeUsers: userCount[0].count,
      popularProgram: popularProgram.length > 0 ? popularProgram[0].program_name : 'None',
      todayDownloads: todayCount[0].count
    });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Download history
app.get('/api/admin/all-downloads', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM download_history ORDER BY downloaded_at DESC LIMIT 100');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Search certificates
app.get('/api/admin/search', async (req, res) => {
  const { q } = req.query;
  
  try {
    const [rows] = await db.execute(`SELECT * FROM certificates 
      WHERE name LIKE ? OR email LIKE ? OR program_name LIKE ? 
      ORDER BY created_at DESC LIMIT 50`,
      [`%${q}%`, `%${q}%`, `%${q}%`]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
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

// Update program expiry
app.post('/api/admin/update-expiry', async (req, res) => {
  const { programId, expiryDate } = req.body;
  
  try {
    await db.execute('UPDATE programs SET expiry_date = ? WHERE id = ?', [expiryDate, programId]);
    res.json({ message: 'Expiry date updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Get certificates
// Get program details
app.get('/api/program-details/:program', async (req, res) => {
  const { program } = req.params;
  
  try {
    const [rows] = await db.execute('SELECT * FROM programs WHERE title = ?', [decodeURIComponent(program)]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Program not found' });
    }
    
    const programData = rows[0];
    res.json({
      title: programData.title,
      dates: programData.dates,
      link: programData.link
    });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/certificates', async (req, res) => {
  const { search } = req.query;
  
  try {
    let query = 'SELECT * FROM certificates ORDER BY created_at DESC';
    let params = [];
    
    if (search) {
      query = 'SELECT * FROM certificates WHERE name LIKE ? OR email LIKE ? OR program_name LIKE ? ORDER BY created_at DESC';
      params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }
    
    const [rows] = await db.execute(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Initialize database and start server
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ MySQL server running on http://localhost:${PORT}`);
  });
});