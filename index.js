const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
dotenv.config({ path: './.env' });

const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const saltRounds = 10;
const app = express();

app.use('/uploads', express.static('public/uploads'));


// --- Add session middleware ---
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false, 
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());


app.use(cors({  origin: '*'}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//Authorization Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token → Forbidden
    req.user = user; // store decoded user info in request
    next();
  });
}

const port = process.env.PORT || 3000;

/*--------------------
      Middlewares
----------------------*/
const jwt = require('jsonwebtoken')

// pool config
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
    ssl: { rejectUnauthorized: false },
});

// Multer config 
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads'); // path folder penyimpanan
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = file.originalname.split('.').pop();
    cb(null, `${req.body.name}-${uniqueSuffix}.${ext}`); // nama file unik
  }
});

const upload = multer({ storage });


// Test DB connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) console.error('Database connection failed:', err);
  else console.log('PostgreSQL connected at', res.rows[0].now);
});


/*--------------------
      Endpoints
----------------------*/

// passport for google Oauth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://calviz-api.up.railway.app/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;

    // Check if user already exists
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user;
    if (result.rows.length === 0) {
      // Insert new user (password null for OAuth users)
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


// Register endpoint
app.post('/register', upload.single('profile'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const profileFile = req.file;
    // Hash the password
    const hashed = await bcrypt.hash(password, saltRounds);

    // Insert ke database, agar tidak terjadi SQL Injection, gunakan parameterized query
    const profileUrl = `/uploads/${profileFile.filename}`;
    const query = `
      insert into users(name, email, password, profile)
      values($1, $2, $3, $4) returning id
    `;
    const values = [name, email, hashed, profileUrl];
    const result = await pool.query(query, values);

    res.status(200).json({ status: 'success', userId: result.rows[0].id, imageUrl: profileUrl});
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Database error' });
  }
});

// login endpoint
app.post('/login', upload.none(), async (req, res) => {
  try {
    const {name, password} = req.body;

    // select from Database
    const query = `
      select * from users
      where name = $1
    `;
    const result = await pool.query(query, [name]);

    if (result.rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // Compare passwords
    const match = await bcrypt.compare(password, result.rows[0].password);
    if (!match) {
      return res.status(401).json({ status: 'error', message: 'Incorrect password' });
    }
    const token = jwt.sign(
        { id: result.rows[0].id, name: result.rows[0].name, email: result.rows[0].email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' } 
    );
    res.json({
      status: 'success',
      message: 'Login successful',
      token, // Stored in Frontend
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/logged', authenticateToken, async (req, res) => {
  // If token valid → req.user contains the decoded info
  res.json({
    message: 'You are logged in!',
    user: req.user
  });
});

// Google Oauth endpoint
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/login-failed',
    session: false, // we’re using JWT, not sessions
  }),
  (req, res) => {
    // Generate a JWT
    const token = jwt.sign(
      {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Redirect user back to frontend with token
    res.redirect(`http://localhost:8000/?token=${token}`);
  }
);



app.get('/login-success', (req, res) => {
  res.send('Google login successful!');
});

app.get('/login-failed', (req, res) => {
  res.send('Google login failed');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
