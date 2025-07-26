const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Test DB connection
db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Connected to MySQL database!');
  }
});

// JWT auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Example route
app.get('/', (req, res) => {
  res.send('Backend is running!');
});

// Get all users (protected, admin only)
app.get('/api/users', authenticateToken, (req, res) => {
  // Only allow admin
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  db.query('SELECT id, name, email, address, role, created_at FROM users', (err, results) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

// Register a new user
app.post('/api/users', async (req, res) => {
  const { name, email, password, address, role } = req.body;
  if (!name || !email || !password || !address || !role) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  // Check if user already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length > 0) return res.status(400).json({ error: 'Email already registered.' });

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    db.query(
      'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, address, role],
      (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.status(201).json({ message: 'User registered successfully!' });
      }
    );
  });
});

// User login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(400).json({ error: 'Invalid email or password.' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid email or password.' });

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Return user info (except password) and token
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        address: user.address,
        role: user.role,
        created_at: user.created_at
      }
    });
  });
});

// Example protected route
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route!', user: req.user });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



// Get all stores (protected: any logged-in user)
app.get('/api/stores', authenticateToken, (req, res) => {
  db.query(
    'SELECT id, name, email, address, owner_id, created_at FROM stores',
    (err, results) => {
      if (err) {
        console.error('Error fetching stores:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(results);
    }
  );
});




// Add a new store (admin only)
app.post('/api/stores', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { name, email, address, owner_id } = req.body;
  if (!name || !email || !address || !owner_id) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  db.query(
    'INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)',
    [name, email, address, owner_id],
    (err, result) => {
      if (err) {
        console.error('Error adding store:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ message: 'Store added successfully!' });
    }
  );
});



// Submit or update a rating (user only)
app.post('/api/ratings', authenticateToken, (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only normal users can rate stores.' });
  }
  const { store_id, rating, comment } = req.body;
  if (!store_id || !rating) {
    return res.status(400).json({ error: 'Store ID and rating are required.' });
  }

  // Check if the user already rated this store
  db.query(
    'SELECT * FROM ratings WHERE user_id = ? AND store_id = ?',
    [req.user.id, store_id],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      if (results.length > 0) {
        // Update existing rating
        db.query(
          'UPDATE ratings SET rating = ?, comment = ? WHERE user_id = ? AND store_id = ?',
          [rating, comment, req.user.id, store_id],
          (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ message: 'Rating updated successfully!' });
          }
        );
      } else {
        // Insert new rating
        db.query(
          'INSERT INTO ratings (user_id, store_id, rating, comment) VALUES (?, ?, ?, ?)',
          [req.user.id, store_id, rating, comment],
          (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ message: 'Rating submitted successfully!' });
          }
        );
      }
    }
  );
});



// Get all ratings for a store
app.get('/api/ratings/:storeId', authenticateToken, (req, res) => {
  const storeId = req.params.storeId;
  db.query(
    `SELECT r.id, r.rating, r.comment, r.created_at, u.name as userName, u.email as userEmail
     FROM ratings r
     JOIN users u ON r.user_id = u.id
     WHERE r.store_id = ?`,
    [storeId],
    (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(results);
    }
  );
});



// Get all ratings for the store(s) owned by the logged-in store owner
app.get('/api/owner/ratings', authenticateToken, (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Access denied' });
  }

  // Find all stores owned by this owner
  db.query(
    'SELECT id FROM stores WHERE owner_id = ?',
    [req.user.id],
    (err, stores) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (stores.length === 0) return res.json([]); // No stores owned

      // Get all ratings for these stores
      const storeIds = stores.map(s => s.id);
      db.query(
        `SELECT r.id, r.rating, r.comment, r.created_at, r.store_id, u.name as userName, u.email as userEmail
         FROM ratings r
         JOIN users u ON r.user_id = u.id
         WHERE r.store_id IN (?)`,
        [storeIds],
        (err, results) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          res.json(results);
        }
      );
    }
  );
});



// Update password (for any logged-in user)
app.post('/api/update-password', authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }

  // Get the user from DB
  db.query('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'User not found.' });

    const user = results[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Current password is incorrect.' });

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password in DB
    db.query(
      'UPDATE users SET password = ? WHERE id = ?',
      [hashedPassword, req.user.id],
      (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: 'Password updated successfully!' });
      }
    );
  });
});