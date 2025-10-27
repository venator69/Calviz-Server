const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const dotenv = require('dotenv');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');

dotenv.config({ path: './.env' });
const saltRounds = 10;
const app = express();

/* --------------------------------
   🔧 BASIC SERVER SETUP
---------------------------------- */
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const allowedOrigins = [
  "https://calviz.vercel.app", 
  "null", 
  "http://localhost:3000",
  "http://localhost:8080", 
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`Not allowed by CORS for origin: ${origin}`), false);
    }
  },
  credentials: true,
}));

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
   🔐 SESSION SETUP
---------------------------------- */
app.use(session({
  store: new PgSession({ pool: pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24*60*60*1000,
    secure: true,
    sameSite: 'none',
    httpOnly: true,
  },
  proxy: true,
}));

/* --------------------------------
   🔍 DEBUG MIDDLEWARE
---------------------------------- */
app.use((req, res, next) => {
  console.log("🧩 Incoming request:", req.method, req.url);
  console.log("🧩 Session before route:", req.session);
  next();
});

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
   👤 AUTH HELPERS
---------------------------------- */
function authenticateSession(req, res, next){
  if(!req.session.user) {
    console.log("❌ No session found, returning 401");
    return res.status(401).json({ message: 'Unauthorized' });
  }
  req.user = req.session.user;
  next();
}

/* --------------------------------
   🔹 PROFILE
---------------------------------- */
app.get('/profile', authenticateSession, async (req, res) => {
  try{
    const result = await pool.query(
      'SELECT name, profile FROM users WHERE id = $1',
      [req.user.id]
    );
    if(result.rows.length === 0) return res.status(404).json({ message: 'User not found' });

    res.json({
      name: result.rows[0].name,
      profile_picture: result.rows[0].profile || '/uploads/default.jpg',
    });
  } catch(err){
    console.error('Profile error:', err);
    res.status(500).json({ message: "Server error" });
  }
});

/* --------------------------------
   🔹 REGISTER
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

    console.log("🧩 New user registered:", result.rows[0].id);

    res.status(200).json({ status: 'success', userId: result.rows[0].id, imageUrl: profileUrl });
  } catch(err){
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

/* --------------------------------
   🔹 LOGIN
---------------------------------- */
app.post("/login", async (req, res) => {
  const { name, password } = req.body || {};
  if(!name || !password) return res.status(400).json({ message: "Name dan password wajib diisi" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if(result.rows.length === 0) return res.status(400).json({ message: "User tidak ditemukan" });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch) return res.status(400).json({ message: "Password salah" });

    req.session.user = { id: user.id, name: user.name };
    console.log("🧩 Session after login:", req.session);

    res.status(200).json({ message: "Login sukses", user: { id: user.id, name: user.name } });
  } catch(err){
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* --------------------------------
   🔹 GOOGLE OAUTH
---------------------------------- */
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "https://calviz-server-production.up.railway.app/auth/google/callback",
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails[0].value;
            const name = profile.displayName;

            let user = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
            if(!user){
                const insert = await pool.query(
                    'INSERT INTO users (name, email, password, profile) VALUES ($1, $2, $3, $4) RETURNING *',
                    [name, email, null, null]
                );
                user = insert.rows[0];
            }
            return done(null, user);
        } catch(err){
            console.error('OAuth error:', err);
            done(err, null);
        }
    }));

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    app.get('/auth/google/callback',
        passport.authenticate('google', { failureRedirect: '/login-failed', session: false }),
        (req, res) => {
            req.session.user = { id: req.user.id, name: req.user.name, email: req.user.email };
            console.log("🧩 Session after Google OAuth:", req.session);
            res.redirect('https://calviz.vercel.app/');
        }
    );
} else {
    console.warn('⚠️ Google OAuth disabled: Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in .env');
}

/* --------------------------------
   🔹 LOGOUT
---------------------------------- */
app.post('/logout', (req, res) => {
  const cookieName = 'connect.sid'; 
  
  req.session.destroy(err => {
    if(err) {
      console.error("❌ Session destroy error:", err);
      return res.status(500).json({ message: "Logout error" });
    }
    
    res.clearCookie(cookieName, { 
      path: '/', 
      secure: true, 
      sameSite: 'none',
    });
    
    console.log("🧩 Session destroyed and cookie cleared");
    res.json({ message: 'Logged out' });
  });
});


/* --------------------------------
   🔹 PROGRESS ENDPOINTS (LABWORKS)
---------------------------------- */
const PROGRESS_API_BASE = '/api/progress';

function isAuthenticated(req, res, next){
  if(!req.session.user) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  req.user = req.session.user;
  next();
}

app.post(`${PROGRESS_API_BASE}/save`, isAuthenticated, async (req, res) => {
    const userId = req.user.id; 
    const { moduleId, status } = req.body;
    
    const columnName = `${moduleId}_check`;
    if (!['riemann_check', 'derivative_check', 'series_check'].includes(columnName)) {
        return res.status(400).json({ message: 'Invalid module ID.' });
    }
    
    try {
        const updateQuery = `
            UPDATE labworks SET ${columnName} = $1 WHERE user_id = $2
        `;
        const updateResult = await pool.query(updateQuery, [status, userId]);

        if (updateResult.rowCount === 0) {
            const insertQuery = `
                INSERT INTO labworks (user_id, ${columnName}) 
                VALUES ($1, $2)
            `;
            await pool.query(insertQuery, [userId, status]);
        }

        res.status(200).json({ success: true, message: `Status module ${moduleId} updated to ${status} in labworks table.` });
    } catch (err) {
        console.error("❌ PROGRESS SAVE ERROR:", err);
        res.status(500).json({ message: "Failed to save progress to server." });
    }
});

app.get(`${PROGRESS_API_BASE}/get`, isAuthenticated, async (req, res) => {
    const userId = req.user.id;

    try {
        const result = await pool.query(
            'SELECT riemann_check, derivative_check, series_check FROM labworks WHERE user_id = $1',
            [userId]
        );
        
        if (result.rows.length === 0) {
             return res.status(200).json({ progress: {} });
        }

        const row = result.rows[0];
        const progressMap = {
            riemann: row.riemann_check,
            derivative: row.derivative_check,
            series: row.series_check
        };

        res.status(200).json({ progress: progressMap });
    } catch (err) {
        console.error("❌ PROGRESS GET ERROR:", err);
        res.status(500).json({ message: "Failed to retrieve progress from server." });
    }
});

/* --------------------------------
   🚀 START SERVER
---------------------------------- */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
