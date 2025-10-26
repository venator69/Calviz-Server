const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const dotenv = require('dotenv');
dotenv.config({ path: './.env' });

const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

const saltRounds = 10;
const app = express();
app.set('trust proxy', 1);

// Upload folder
const uploadFolder = 'public/uploads';
if (!fs.existsSync(uploadFolder)) {
  fs.mkdirSync(uploadFolder, { recursive: true });
}
app.use('/uploads', express.static('public/uploads'));

// Middlewares
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: "https://calviz.vercel.app",
  credentials: true,
}));

// Session (untuk passport)
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL pool
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = file.originalname.split('.').pop();
    cb(null, `${req.body.name}-${uniqueSuffix}.${ext}`);
  },
});
const upload = multer({ storage });

// DB test
pool.query('SELECT NOW()', (err, res) => {
  if (err) console.error('Database connection failed:', err);
  else console.log('PostgreSQL connected at', res.rows[0].now);
});

/*--------------------
  AUTH TOKEN CHECK
----------------------*/
function authenticateToken(req, res, next) {
  const token = req.cookies.token; // 🔥 ambil token dari cookie
  if (!token) return res.status(401).json({ message: 'No token found' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

/*--------------------
      ENDPOINTS
----------------------*/

// PROFILE
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT name, profile FROM users WHERE id=$1',
      [req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json({
      name: result.rows[0].name,
      profile_picture: result.rows[0].profile || '/uploads/default.jpg'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/*--------------------
   REGISTER
----------------------*/
app.post('/register', upload.single('profile'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const profileFile = req.file;
    const hashed = await bcrypt.hash(password, saltRounds);
    const profileUrl = profileFile ? `/uploads/${profileFile.filename}` : null;

    const query = `
      INSERT INTO users(name, email, password, profile)
      VALUES($1, $2, $3, $4)
      RETURNING id
    `;
    const values = [name, email, hashed, profileUrl];
    const result = await pool.query(query, values);

    res.status(200).json({
      status: 'success',
      userId: result.rows[0].id,
      imageUrl: profileUrl
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

/*--------------------
   LOGIN (manual)
----------------------*/
// login endpoint
app.post("/login", upload.none(), async (req, res)=> {
  const { name, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // Cookie setup for Vercel Railway
res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  });

    console.log("Cookie set:", res.getHeaders()["set-cookie"]);
    return res.json({ status: "success", message: "Login successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


/*--------------------
  GOOGLE OAUTH
----------------------*/
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://calviz-server-production.up.railway.app/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    let user;
    if (result.rows.length === 0) {
      const insert = await pool.query(
        'INSERT INTO users (name, email, password, profile) VALUES ($1, $2, $3, $4) RETURNING *',
        [name, email, null, null]
      );
      user = insert.rows[0];
    } else {
      user = result.rows[0];
    }
    return done(null, user);
  } catch (err) {
    console.error('OAuth error:', err);
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  done(null, user.rows[0]);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-failed', session: false }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, name: req.user.name, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Kirim token ke browser sebagai cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/',
      domain: '.railway.app', // ⬅️ tambahkan ini
    });

    res.json({ message: "Login successful" });


    // Redirect kembali ke frontend tanpa token di URL
    res.redirect("https://calviz.vercel.app/");
  }
);


/*--------------------
   LOGOUT
----------------------*/
app.post('/logout', (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none"
  });
  res.json({ message: "Logged out" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
