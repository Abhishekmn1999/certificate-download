const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

// In-memory storage
let programs = [];
let certificates = [];
let otps = [];
let admins = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'superadmin', password: 'super123', role: 'super_admin' }
];

// Load certificates from files
function loadCertificates() {
  const certDir = path.join(__dirname, 'certificates');
  if (fs.existsSync(certDir)) {
    const files = fs.readdirSync(certDir);
    files.forEach(file => {
      if (file.endsWith('.pdf')) {
        const name = file.replace(' - Certificate.pdf', '');
        certificates.push({
          id: certificates.length + 1,
          program_name: 'Default Program',
          name: name,
          email: name.toLowerCase().replace(/\s+/g, '.') + '@example.com',
          certificate_path: path.join(certDir, file),
          created_at: new Date().toISOString()
        });
      }
    });
  }
}

loadCertificates();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mnabhishek99@gmail.com',
    pass: 'bummxatjzrqkdktd'
  }
});

let currentAdminSession = null;

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/admin-login', (req, res) => {
  const { username, password } = req.body;
  
  const admin = admins.find(a => a.username === username && a.password === password);
  
  if (!admin) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  currentAdminSession = admin;
  
  res.json({ 
    message: 'Login successful', 
    role: admin.role,
    username: admin.username
  });
});

app.get('/api/programs', (req, res) => {
  if (programs.length === 0) {
    const uniquePrograms = [...new Set(certificates.map(c => c.program_name))];
    res.json(uniquePrograms.map(p => ({ title: p, link: '', dates: '' })));
  } else {
    res.json(programs);
  }
});

app.get('/api/admin/programs', (req, res) => {
  res.json(programs);
});

app.post('/api/admin/programs', (req, res) => {
  const { title, link, dates, expiry_date } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Program title is required' });
  }
  
  const newProgram = {
    id: programs.length + 1,
    title,
    link: link || '',
    dates: dates || '',
    created_by: currentAdminSession ? currentAdminSession.username : 'admin',
    expiry_date: expiry_date || null,
    created_at: new Date().toISOString()
  };
  
  programs.push(newProgram);
  
  res.json({ message: 'Program added successfully', id: newProgram.id });
});

app.delete('/api/admin/programs/:id', (req, res) => {
  const { id } = req.params;
  const index = programs.findIndex(p => p.id == id);
  
  if (index === -1) {
    return res.status(404).json({ error: 'Program not found' });
  }
  
  programs.splice(index, 1);
  res.json({ message: 'Program deleted successfully' });
});

app.put('/api/admin/programs/:id', (req, res) => {
  const { id } = req.params;
  const { expiry_date } = req.body;
  
  const program = programs.find(p => p.id == id);
  
  if (!program) {
    return res.status(404).json({ error: 'Program not found' });
  }
  
  program.expiry_date = expiry_date;
  res.json({ message: 'Program updated successfully' });
});

app.get('/api/admin/stats', (req, res) => {
  res.json({
    totalPrograms: programs.length,
    totalCertificates: certificates.length
  });
});

app.get('/api/admin/certificates', (req, res) => {
  const { search } = req.query;
  
  let result = certificates;
  
  if (search) {
    result = certificates.filter(c => 
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.email.toLowerCase().includes(search.toLowerCase()) ||
      c.program_name.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  res.json(result);
});

app.get('/api/admin/users', (req, res) => {
  res.json(admins.map(a => ({ id: a.id, username: a.username, role: a.role })));
});

app.post('/api/admin/users', (req, res) => {
  const { username, password, email, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  if (admins.find(a => a.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  const newUser = {
    id: admins.length + 1,
    username,
    password,
    email: email || '',
    role: role || 'admin'
  };
  
  admins.push(newUser);
  
  res.json({ message: 'User created successfully', id: newUser.id });
});

app.delete('/api/admin/users/:id', (req, res) => {
  const { id } = req.params;
  const index = admins.findIndex(a => a.id == id);
  
  if (index === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  admins.splice(index, 1);
  res.json({ message: 'User deleted successfully' });
});

app.post('/api/request-certificate', (req, res) => {
  const { programName, name, email } = req.body;
  
  const cert = certificates.find(c => 
    c.program_name === programName && 
    c.email.toLowerCase() === email.toLowerCase() && 
    c.name === name
  );
  
  if (!cert) {
    return res.status(404).json({ error: 'Certificate not found' });
  }
  
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  
  otps.push({
    id: otps.length + 1,
    email: email.toLowerCase(),
    otp,
    expires_at: expiresAt,
    verified: false
  });
  
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

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  
  const otpRecord = otps.find(o => 
    o.email === email.toLowerCase() && 
    o.otp === otp && 
    o.expires_at > new Date() && 
    !o.verified
  );
  
  if (!otpRecord) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }
  
  otpRecord.verified = true;
  
  const cert = certificates.find(c => c.email.toLowerCase() === email.toLowerCase());
  
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

app.get('/api/download-certificate/:id', (req, res) => {
  const { id } = req.params;
  
  const cert = certificates.find(c => c.id == id);
  
  if (!cert) {
    return res.status(404).json({ error: 'Certificate not found' });
  }
  
  if (!fs.existsSync(cert.certificate_path)) {
    return res.status(404).json({ error: 'Certificate file not found' });
  }
  
  const filename = `${cert.name} - certificate.pdf`;
  res.download(path.resolve(cert.certificate_path), filename);
});

app.listen(PORT, () => {
  console.log(`✅ Simple server running on http://localhost:${PORT}`);
  console.log(`📊 Loaded ${certificates.length} certificates`);
});