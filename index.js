require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'pefge7-vogCas-kondyg'; // replace key with env variable in production


console.log('STARTING index.js');


console.log('Loading fs...');
const fs = require('fs');
console.log('Loading bcryptjs...');
const bcrypt = require('bcryptjs');
console.log('Loading express...');
const express = require('express');

const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const PORT = 3001;

app.use(express.json());
app.use(cors());

// Initialize SQLite database
const path = require('path'); 
const db = new sqlite3.Database('C:/Users/Vincent/CodeVault/codevault-backend/database/codevault.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    // Create users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);
    // Create snippets table
    db.run(`
      CREATE TABLE IF NOT EXISTS snippets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        code TEXT NOT NULL,
        language TEXT NOT NULL,
        tags TEXT,
        is_public INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
  }
});

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to CodeVault backend!');
});

// Signup route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  if (!strongPasswordRegex.test(password)) {
    return res.status(400).json({
      message:
        'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.'
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint')) {
            return res.status(409).json({ message: 'User already exists' });
          }
          console.error('Error saving user:', err);
          return res.status(500).json({ message: 'Server error saving user' });
        }
        res.status(201).json({ message: 'User created successfully' });
      }
    );
  } catch (error) {
    console.error('Error hashing password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Server error' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Snippet CRUD endpoints
// Create snippet
app.post('/snippets', authenticate, (req, res) => {
  const { title, code, language, tags, is_public } = req.body;
  if (!title || !code || !language) {
    return res.status(400).json({ message: 'Title, code, and language required' });
  }

  db.run(
    'INSERT INTO snippets (user_id, title, code, language, tags, is_public) VALUES (?, ?, ?, ?, ?, ?)',
    [req.user.userId, title, code, language, tags?.join(','), is_public ? 1 : 0],
    function(err) {
      if (err) {
        console.error('Error creating snippet:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      res.status(201).json({ id: this.lastID, message: 'Snippet created' });
    }
  );
});

// Get all snippets for user
app.get('/snippets', authenticate, (req, res) => {
  db.all(
    'SELECT * FROM snippets WHERE user_id = ?',
    [req.user.userId],
    (err, snippets) => {
      if (err) {
        console.error('Error fetching snippets:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      res.json(snippets);
    }
  );
});

// Get single snippet
app.get('/snippets/:id', authenticate, (req, res) => {
  db.get(
    'SELECT * FROM snippets WHERE id = ? AND (user_id = ? OR is_public = 1)',
    [req.params.id, req.user.userId],
    (err, snippet) => {
      if (err) {
        console.error('Error fetching snippet:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      if (!snippet) {
        return res.status(404).json({ message: 'Snippet not found or unauthorized' });
      }
      res.json(snippet);
    }
  );
});

// Update snippet
app.put('/snippets/:id', authenticate, (req, res) => {
  const { title, code, language, tags, is_public } = req.body;
  db.run(
    'UPDATE snippets SET title = ?, code = ?, language = ?, tags = ?, is_public = ? WHERE id = ? AND user_id = ?',
    [title, code, language, tags?.join(','), is_public ? 1 : 0, req.params.id, req.user.userId],
    function(err) {
      if (err) {
        console.error('Error updating snippet:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'Snippet not found or unauthorized' });
      }
      res.json({ message: 'Snippet updated' });
    }
  );
});

// Delete snippet
app.delete('/snippets/:id', authenticate, (req, res) => {
  db.run(
    'DELETE FROM snippets WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.userId],
    function(err) {
      if (err) {
        console.error('Error deleting snippet:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'Snippet not found or unauthorized' });
      }
      res.json({ message: 'Snippet deleted' });
    }
  );
});

// Toggle public/private status
app.patch('/snippets/:id/toggle-public', authenticate, (req, res) => {
  // First get the current value
  db.get(
    'SELECT is_public FROM snippets WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.userId],
    (err, row) => {
      if (err) {
        console.error('Error finding snippet:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      if (!row) {
        return res.status(404).json({ message: 'Snippet not found or unauthorized' });
      }

      const newStatus = row.is_public ? 0 : 1;
      db.run(
        'UPDATE snippets SET is_public = ? WHERE id = ? AND user_id = ?',
        [newStatus, req.params.id, req.user.userId],
        function(err) {
          if (err) {
            console.error('Error updating visibility:', err);
            return res.status(500).json({ message: 'Server error' });
          }
          res.json({ message: `Snippet is now ${newStatus ? 'public' : 'private'}` });
        }
      );
    }
  );
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});