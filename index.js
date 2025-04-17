require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB successfully');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

const JWT_SECRET = process.env.JWT_SECRET; // In production, use environment variables

// API Routes
app.get('/api/users', async (req, res) => {
  try {
    console.log('Fetching users from database...');
    const users = await User.find({}, '-password -__v');
    
    // Generate token and format response for each user
    const formattedUsers = users.map(user => {
      const token = jwt.sign(
        { id: user._id, username: user.username },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      return {
        id: user._id,
        username: user.username,
        token: token
      };
    });
    
    return res.status(200).json({
      success: true,
      data: formattedUsers
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

// Session middleware - after API routes
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: new session.MemoryStore(),
  cookie: { secure: false }
}));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Home route
app.get('/', (req, res) => {
  if (req.session.isAuthenticated) {
    res.redirect('/dashboard');
  } else {
    res.send(`
      <h1>Welcome</h1>
      <a href="/login">Login</a> | <a href="/register">Register</a>
    `);
  }
});

// Register form route
app.get('/register', (req, res) => {
  console.log('Register page accessed');
  res.send(`
    <h1>Register</h1>
    <form method="POST" action="/register">
      <input type="text" name="username" placeholder="Username" required><br>
      <input type="password" name="password" placeholder="Password" required><br>
      <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="/login">Login</a></p>
  `);
});

// Register POST route
app.post('/register', async (req, res) => {
  try {
    console.log('Register POST route hit:', req.body);
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.send('Username and password are required. <a href="/register">Try again</a>');
    }

    const userExists = await User.findOne({ username });
    
    if (userExists) {
      return res.send('Username already exists. <a href="/register">Try again</a>');
    }

    const user = new User({ username, password });
    await user.save();
    console.log('User registered successfully:', username);
    res.redirect('/login');
  } catch (error) {
    console.error('Registration error:', error);
    res.send(`Error creating user: ${error.message}. <a href="/register">Try again</a>`);
  }
});

// Login form route
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Username" required><br>
      <input type="password" name="password" placeholder="Password" required><br>
      <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="/register">Register</a></p>
  `);
});

// Login POST route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.send('Invalid credentials. <a href="/login">Try again</a>');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.send('Invalid credentials. <a href="/login">Try again</a>');
    }

    req.session.isAuthenticated = true;
    req.session.username = username;
    res.redirect('/dashboard');
  } catch (error) {
    res.send('Error during login. <a href="/login">Try again</a>');
  }
});

// Simple authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.isAuthenticated) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Protected dashboard route
app.get('/dashboard', requireAuth, (req, res) => {
  res.send(`
    <h1>Welcome ${req.session.username}!</h1>
    <p>This is your protected dashboard.</p>
    <a href="/logout">Logout</a>
  `);
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:3000`);
});
