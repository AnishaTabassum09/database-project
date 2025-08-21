const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const pool = require('./db/pool'); // PostgreSQL pool file
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ===================== Middleware =====================
app.use(express.static(path.join(__dirname, '../frontend')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: '1234',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// ===================== Serve Requests Pages =====================

// User requests page
app.get('/requests', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/requests.html'));
});

// Admin requests page
app.get('/admin/requests', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/bookRequests.html'));
});

// Add this route for /bookRequests
app.get('/bookRequests', (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, '../frontend/bookRequests.html'));
});

// User feedback page
app.get('/feedback', (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'user') {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, '../frontend/userFeedback.html'));
});

// Admin feedback page
app.get('/adminFeedback', (req, res) => {
  console.log('Session user:', req.session.user); // Debug line
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, '../frontend/adminFeedback.html'));
});


// ===================== Auth Pages =====================
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

// ===================== SIGNUP =====================
app.post('/signup', async (req, res) => {
  const { fullname, email, password, confirmPassword, accountType } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send('❌ Passwords do not match!');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (fullname, email, password, account_type) VALUES ($1, $2, $3, $4)',
      [fullname, email, hashedPassword, accountType]
    );
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error: Email may already exist or server error.');
  }
});

// ===================== LOGIN =====================
app.post('/login', async (req, res) => {
  const { email, password, accountType } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND account_type = $2',
      [email, accountType]
    );

    if (result.rows.length === 0) {
      return res.status(401).send('❌ Invalid email or account type.');
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).send('❌ Incorrect password.');
    }

    req.session.user = user; // Save to session

    // Redirect based on account type
    if (user.account_type === 'admin') {
      res.redirect('/dashboard');
    } else if (user.account_type === 'user') {
      res.redirect('/userDashboard');
    } else {
      res.redirect('/login');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// ===================== DASHBOARD PAGES =====================
app.get('/dashboard', (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, '../frontend/dashboard.html'));
});

app.get('/userDashboard', (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'user') {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, '../frontend/userDashboard.html'));
});

// ===================== Dashboard Stats API (Admin) =====================
app.get('/api/dashboard-stats', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const totalBooks = await pool.query('SELECT COUNT(*) FROM books');
    const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
    const issuedBooks = await pool.query('SELECT COUNT(*) FROM issuedBooks');
    const overdueBooks = await pool.query(
      'SELECT COUNT(*) FROM issuedBooks WHERE due_date < NOW() AND return_date IS NULL'
    );
    const newUsers = await pool.query(
      "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - interval '7 days'"
    );
    const booksCurrentlyBorrowed = await pool.query(
      'SELECT COUNT(*) FROM issuedBooks WHERE return_date IS NULL'
    );
    const topBooks = await pool.query(`
      SELECT title, COUNT(*) AS borrow_count
      FROM issuedBooks
      WHERE issue_date >= NOW() - interval '30 days'
      GROUP BY title
      ORDER BY borrow_count DESC
      LIMIT 5
    `);

    res.json({
      totalBooks: totalBooks.rows[0].count,
      totalUsers: totalUsers.rows[0].count,
      booksCurrentlyBorrowed: booksCurrentlyBorrowed.rows[0].count,
      issuedBooks: issuedBooks.rows[0].count,
      overdueBooks: overdueBooks.rows[0].count,
      newUsers: newUsers.rows[0].count,
      topBooks: topBooks.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching dashboard stats' });
  }
});

// ===================== User Dashboard API =====================
app.get('/api/userDashboard-stats', async (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'user') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const issuedBooks = await pool.query(
      `SELECT issue_id, title, issue_date, due_date, return_date
       FROM issuedBooks
       WHERE id = $1
       ORDER BY issue_date DESC`,
      [req.session.user.id]
    );

    res.json({
      fullname: req.session.user.fullname,
      email: req.session.user.email,
      issuedBooks: issuedBooks.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching user dashboard data' });
  }
});

// ===================== Admin Books Page =====================
app.get('/books', (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.redirect('/login');  // Block non-admins
  }
  res.sendFile(path.join(__dirname, '../frontend/books.html'));
});

// ===================== Admin Books API (CRUD) =====================

// Get all books (only admins)
app.get('/api/books', async (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const result = await pool.query('SELECT * FROM books ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching books:', err);
    res.status(500).json({ error: 'Error fetching books' });
  }
});

// Add new book (only admins)
app.post('/api/books', async (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { title, author, isbn, copies, status } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO books (title, author, isbn, copies, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, author, isbn, copies, status]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error adding book:', err);
    res.status(500).json({ error: 'Error adding book' });
  }
});

// Update book (only admins)
app.put('/api/books/:id', async (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id } = req.params;
  const { title, author, isbn, copies, status } = req.body;

  try {
    const result = await pool.query(
      'UPDATE books SET title=$1, author=$2, isbn=$3, copies=$4, status=$5 WHERE id=$6 RETURNING *',
      [title, author, isbn, copies, status, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating book:', err);
    res.status(500).json({ error: 'Error updating book' });
  }
});

// Delete book (only admins)
app.delete('/api/books/:id', async (req, res) => {
  if (!req.session.user || req.session.user.account_type !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { id } = req.params;

  try {
    await pool.query('DELETE FROM books WHERE id=$1', [id]);
    res.json({ message: 'Book deleted successfully' });
  } catch (err) {
    console.error('Error deleting book:', err);
    res.status(500).json({ error: 'Error deleting book' });
  }
});

// ===================== User Books Page =====================
app.get('/userBooks', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login'); // block if not logged in
  }
  res.sendFile(path.join(__dirname, '../frontend/userBooks.html'));
});

// ===================== User Books API (Read-Only) =====================
app.get('/api/userBooks', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    // Users can only view books, not modify
    const result = await pool.query(
      'SELECT id, title, author, isbn, copies, status FROM books ORDER BY id'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching user books:', err);
    res.status(500).json({ error: 'Error fetching user books' });
  }
});


// ===================== Users Pages =====================
app.get('/users', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, '../frontend/users.html'));
});

app.get('/edit-user.html', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, '../frontend/edit-user.html'));
});

// ===================== Issued Books Page =====================
app.get('/issuedBooks', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, '../frontend/issuedBooks.html'));
});

// ===================== Books API =====================
app.get('/api/books', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const result = await pool.query('SELECT * FROM books ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching books' });
  }
});

app.post('/api/books', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { title, author, isbn, copies, status } = req.body;

  if (!title || !author || !isbn || isNaN(copies) || copies < 1 || !status) {
    return res.status(400).json({ error: 'Invalid book data' });
  }

  try {
    await pool.query(
      'INSERT INTO books (title, author, isbn, copies, status) VALUES ($1, $2, $3, $4, $5)',
      [title, author, isbn, copies, status]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error adding book' });
  }
});

app.put('/api/books/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;
  const { title, author, isbn, copies, status } = req.body;

  if (!title || !author || !isbn || isNaN(copies) || copies < 1 || !status) {
    return res.status(400).json({ error: 'Invalid book data' });
  }

  try {
    await pool.query(
      'UPDATE books SET title = $1, author = $2, isbn = $3, copies = $4, status = $5 WHERE id = $6',
      [title, author, isbn, copies, status, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error updating book' });
  }
});

app.delete('/api/books/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;

  try {
    await pool.query('DELETE FROM books WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error deleting book' });
  }
});

// ===================== Users API =====================
app.get('/api/users', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const result = await pool.query(
      'SELECT id, fullname, email, account_type, status FROM users ORDER BY id'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching users' });
  }
});

app.post('/api/users', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { fullname, email, password, account_type, status } = req.body;

  if (!fullname || !email || !password || !account_type || !status) {
    return res.status(400).json({ error: 'Invalid user data' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (fullname, email, password, account_type, status) VALUES ($1, $2, $3, $4, $5)',
      [fullname, email, hashedPassword, account_type, status]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error adding user (possible duplicate email)' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;

  try {
    const result = await pool.query(
      'SELECT id, fullname, email, account_type, status FROM users WHERE id = $1',
      [id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching user' });
  }
});

app.put('/api/users/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;
  const { fullname, email, account_type, status } = req.body;

  if (!fullname || !email || !account_type || !status) {
    return res.status(400).json({ error: 'Invalid user data' });
  }

  try {
    const checkEmail = await pool.query(
      'SELECT id FROM users WHERE email = $1 AND id != $2',
      [email, id]
    );
    if (checkEmail.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    await pool.query(
      'UPDATE users SET fullname = $1, email = $2, account_type = $3, status = $4 WHERE id = $5',
      [fullname, email, account_type, status, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error updating user' });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;

  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error deleting user' });
  }
});

// ===================== Issued Books API =====================
app.get('/api/issuedBooks', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const result = await pool.query(
      `SELECT issue_id, title, fullname, issue_date, due_date, return_date
      FROM issuedBooks
      ORDER BY issue_id`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching issued books' });
  }
});

app.post('/api/issuedBooks', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { title, id, fullname, due_date } = req.body;

  if (!title || !id || !fullname || !due_date) {
    return res.status(400).json({ error: 'Invalid issued book data' });
  }

  try {
    await pool.query(
      'INSERT INTO issuedBooks (title, id, fullname, due_date) VALUES ($1, $2, $3, $4)',
      [title, id, fullname, due_date]
    );
    res.json({ success: true, message: 'Book issued successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error issuing book' });
  }
});

app.put('/api/issuedBooks/:id/return', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;

  try {
    await pool.query(
      'UPDATE issuedBooks SET return_date = NOW() WHERE issue_id = $1',
      [id]
    );
    res.json({ success: true, message: 'Book returned successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error updating issued book return' });
  }
});

app.delete('/api/issuedBooks/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { id } = req.params;

  try {
    await pool.query('DELETE FROM issuedBooks WHERE issue_id = $1', [id]);
    res.json({ success: true, message: 'Issued book deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error deleting issued book' });
  }
});

// ===================== Payments Routes =====================

// Serve the payments.html page on /payments
app.get('/payments', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/payments.html'));
});

// Get all payments
app.get('/api/payments', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM payments ORDER BY payments_id ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching payments:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single payment by ID
app.get('/api/payments/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM payments WHERE payments_id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching payment:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add new payment
app.post('/api/payments', async (req, res) => {
  const { issue_id, amount, is_paid, imposed_date, paid_date } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO payments (issue_id, amount, is_paid, imposed_date, paid_date)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [issue_id, amount, is_paid, imposed_date, paid_date]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error inserting payment:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update payment
app.put('/api/payments/:id', async (req, res) => {
  const { id } = req.params;
  const { issue_id, amount, is_paid, imposed_date, paid_date } = req.body;
  try {
    const result = await pool.query(
      `UPDATE payments
      SET issue_id = $1, amount = $2, is_paid = $3, imposed_date = $4, paid_date = $5
      WHERE payments_id = $6 RETURNING *`,
      [issue_id, amount, is_paid, imposed_date, paid_date, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating payment:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete payment
app.delete('/api/payments/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM payments WHERE payments_id = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.json({ message: 'Payment deleted successfully' });
  } catch (err) {
    console.error('Error deleting payment:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===================== User Dashboard & Requests =====================

// Get logged-in user info (for sidebar)
app.get('/api/user/dashboard', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    res.json({ user: req.session.user });
  } catch (err) {
    console.error('Error fetching user dashboard:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add this route for /api/user-dashboard (for frontend compatibility)
app.get('/api/user-dashboard', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ user: req.session.user });
});

// Get available books for users
app.get('/api/user/books', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, author, isbn, copies, status
       FROM books
       ORDER BY title ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching books:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Request a book (user creates new request)
app.post('/api/requests', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    const { title, author } = req.body;

    if (!title || title.trim() === '') {
      return res.status(400).json({ error: 'Book title is required' });
    }

    const insertRes = await pool.query(
      `INSERT INTO book_requests (user_id, title, author, status, request_date)
       VALUES ($1, $2, $3, 'Pending', NOW())
       RETURNING id, title, author, status, request_date`,
      [
        req.session.user.id,
        title.trim(),
        author && author.trim() !== '' ? author.trim() : null
      ]
    );

    res.json(insertRes.rows[0]);
  } catch (err) {
    console.error('Error requesting book:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get requests for the logged-in user
app.get('/api/requests', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    const result = await pool.query(
      `SELECT id, title, author, request_date, status
       FROM book_requests
       WHERE user_id = $1
       ORDER BY request_date DESC`,
      [req.session.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching user requests:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===================== FEEDBACK ROUTES =====================

// User submits feedback (from user dashboard)
app.post('/api/user/feedback', async (req, res) => {
  try {
    // Check if user is logged in and is a normal user
    if (!req.session.user || req.session.user.account_type !== 'user') {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { feedback_text, rating } = req.body;

    // Validate feedback_text and rating
    if (!feedback_text || !rating) {
      return res.status(400).json({ error: 'Feedback text and rating are required.' });
    }

    const numericRating = Number(rating);
    if (isNaN(numericRating) || numericRating < 1 || numericRating > 5) {
      return res.status(400).json({ error: 'Rating must be a number between 1 and 5.' });
    }

    // Insert feedback into database
    await pool.query(
      `INSERT INTO feedback (users_id, feedback_text, rating, feedback_date)
       VALUES ($1, $2, $3, NOW())`,
      [req.session.user.id, feedback_text.trim(), numericRating]
    );

    res.json({ success: true, message: 'Feedback submitted successfully.' });
  } catch (err) {
    console.error('Error submitting feedback:', err);
    res.status(500).json({ error: 'Server error while submitting feedback.' });
  }
});


// User gets their own feedbacks
app.get('/api/user/feedback', async (req, res) => {
  try {
    // Check if user is logged in and is a normal user
    if (!req.session.user || req.session.user.account_type !== 'user') {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Fetch feedback for the logged-in user
    const result = await pool.query(
      `SELECT feedback_id, feedback_text, rating, feedback_date
       FROM feedback
       WHERE users_id = $1
       ORDER BY feedback_date DESC`,
      [req.session.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching user feedback:', err);
    res.status(500).json({ error: 'Server error while fetching feedback.' });
  }
});


// Admin gets all feedbacks (for admin dashboard)
app.get('/api/admin/feedback', async (req, res) => {
  try {
    // Check if user is logged in and is an admin
    if (!req.session.user || req.session.user.account_type !== 'admin') {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Fetch all feedback with user details for admin view
    const result = await pool.query(
      `SELECT f.feedback_id, f.users_id, u.fullname, f.feedback_text, f.rating, f.feedback_date
       FROM feedback f
       LEFT JOIN users u ON f.users_id = u.id
       ORDER BY f.feedback_date DESC`
    );

    // Send only the fields needed for your table
    const formattedData = result.rows.map(row => ({
      users_id: row.users_id,
      fullname: row.fullname || 'Unknown',
      feedback_text: row.feedback_text,
      rating: row.rating,
      feedback_date: row.feedback_date
    }));

    res.json(formattedData);
  } catch (err) {
    console.error('Error fetching all feedback:', err);
    res.status(500).json({ error: 'Server error while fetching all feedback.' });
  }
});

// ===================== ADMIN ROUTES =====================

// Get all book requests (admin view)
app.get('/api/admin/requests', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.account_type !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const result = await pool.query(
      `SELECT r.id,
              u.fullname AS user_name,
              r.title,
              r.author,
              r.request_date,
              r.status
       FROM book_requests r
       JOIN users u ON r.user_id = u.id
       ORDER BY r.request_date DESC`
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching admin requests:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update request status (Approve/Reject)
app.post('/api/admin/requests/:id/status', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.account_type !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { id } = req.params;
    const { status } = req.body;

    if (!['Approved', 'Rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const updateRes = await pool.query(
      `UPDATE book_requests
       SET status = $1
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );

    if (updateRes.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }

    res.json(updateRes.rows[0]);
  } catch (err) {
    console.error('Error updating request status:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// ===================== User Info API =====================
app.get('/api/user', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json(req.session.user);
});

// ===================== LOGOUT =====================
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      return res.send('Error logging out.');
    }
    res.redirect('/login');
  });
});

// ===================== Start Server =====================
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
