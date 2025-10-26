const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const jwt = require('jsonwebtoken');

dotenv.config({ path: './.env' });

const saltRounds = 10;
const app = express();

/* --------------------------------
   🔧 BASIC SERVER SETUP
---------------------------------- */
app.set('trust proxy', 1); // Needed for secure cookies behind proxy (Railway)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ✅ CORS setup for frontend <-> backend cookies
app.use(cors({
  origin: "https://calviz.vercel.app",
  credentials: true,
}));

/* --------------------------------
   📁 FILE UPLOAD SETUP
---------------------------------- */
const uploadFolder = 'public/uploads';
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder, { recursive: true });
app.use('/uploads', express.static('public/uploads'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads'),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = file.originalname.split('.').pop();
    cb(null, `${req.body.name}-${unique}.${ext}`);
  },
});
const upload = multer({ storage });

/* --------------------------------
   🗄️ DATABASE CONNECTION
---------------------------------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.query('SELECT NOW()', (err, res) => {
  if (err) console.error('❌ Database connection failed:', err);
  else console.log('✅ PostgreSQL connected at', res.rows[0].now);
});

/* --------------------------------
   🔐 JWT AUTH MIDDLEWARE
---------------------------------- */
function authenticateToken(req, res, next) {
  console.log("🧩 Incoming cookies:", req.cookies);
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'No token found' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

/* --------------------------------
   👤 USER PROFILE
---------------------------------- */
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT name, profile FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json({
      name: result.rows[0].name,
      profile_picture: result.rows[0].profile || '/uploads/default.jpg',
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ message: "Server error" });
  }
});

/* --------------------------------
   📝 REGISTER
---------------------------------- */
app.post('/register', upload.single('profile'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, saltRounds);
    const profileUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const result = await pool.query(
      'INSERT INTO users(name, email, password, profile) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, email, hashed, profileUrl]
    );

    res.status(200).json({
      status: 'success',
      userId: result.rows[0].id,
      imageUrl: profileUrl,
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

/* --------------------------------
   🔑 LOGIN
---------------------------------- */
app.post('/login', upload.none(), async (req, res) => {
  const { name, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE name = $1', [name]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // ✅ Set cookie properly for Railway + Vercel
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000,
    });

    console.log("🍪 Cookie set:", res.getHeaders()['set-cookie']);
    res.json({ status: 'success', message: 'Login successful' });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* --------------------------------
   🌐 GOOGLE OAUTH
---------------------------------- */
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://calviz-server-production.up.railway.app/auth/google/callback",
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;

    let user = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
    if (!user) {
      const insert = await pool.query(
        'INSERT INTO users (name, email, password, profile) VALUES ($1, $2, $3, $4) RETURNING *',
        [name, email, null, null]
      );
      user = insert.rows[0];
    }
    return done(null, user);
  } catch (err) {
    console.error('OAuth error:', err);
    done(err, null);
  }
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-failed', session: false }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, name: req.user.name, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/',
    });

    res.redirect('https://calviz.vercel.app/');
  }
);

/* --------------------------------
   🚪 LOGOUT
---------------------------------- */
app.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
    path: '/',
  });
  res.json({ message: 'Logged out' });
});

/* --------------------------------
   🚀 START SERVER
---------------------------------- */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
