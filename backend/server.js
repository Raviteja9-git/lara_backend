import express from 'express';
import bodyParser from 'body-parser';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { PDFDocument, rgb } from 'pdf-lib';
import dotenv from 'dotenv';
import * as fontkit from 'fontkit';
import axios from 'axios';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import otpGenerator from 'otp-generator';
import { body, validationResult } from 'express-validator';


const app = express();
app.use(cors());
app.use(bodyParser.json());

// Load environment variables
dotenv.config();

const SECRET_KEY = process.env.SECRET_KEY; // Replace with an environment variable in production

// Create a MySQL connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST, // Your database host
  user: process.env.DB_USER, // Your database user
  password: process.env.DB_PASSWORD, // Your database password
  database: process.env.DB_NAME, // Your database name
  charset: 'utf8mb4', // Ensures support for emojis and special characters
  waitForConnections: true, // Wait for connections if none are available
  connectionLimit: 10, // Maximum number of connections in the pool
  queueLimit: 0, // Unlimited number of queued connection requests
});

// Function to keep the database connection alive
const keepDatabaseAlive = async () => {
  try {
    const connection = await db.getConnection();
    await connection.query('SELECT 1'); // Simple keep-alive query
    connection.release(); // Release the connection back to the pool
    //console.log('Database connection is active.');
  } catch (error) {
    console.error('Error in keep-alive query:', error.message);
    reconnectDatabase(); // Attempt to reconnect if the query fails
  }
};

// Reconnect to the database in case of connection issues
const reconnectDatabase = async () => {
  try {
    console.log('Attempting to reconnect to the database...');
    const connection = await db.getConnection();
    console.log('Reconnected to the MySQL database successfully!');
    connection.release();
  } catch (error) {
    console.error('Failed to reconnect to the database:', error.message);
    setTimeout(reconnectDatabase, 5000); // Retry after 5 seconds
  }
};

// Test the initial connection at server startup
(async () => {
  try {
    const connection = await db.getConnection();
    console.log('Connected to MySQL database successfully!');
    connection.release();
  } catch (error) {
    console.error('Failed to connect to the MySQL database:', error.message);
    reconnectDatabase(); // Attempt to reconnect at startup
  }
})();

// Schedule the keep-alive query to run every 10 seconds
setInterval(keepDatabaseAlive, 10000); // Adjust the interval as needed



// Middleware: Authenticate Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.error('No token provided');
    return res.status(401).send('Access Denied');
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.error('Invalid Token:', err.message);
      return res.status(403).send('Invalid Token');
    }
    req.user = user;
    next();
  });
};

// In-memory OTP store (Replace with a database in production)
const OTP_STORE = {};

// Endpoint: Send OTP
app.post(
  '/api/send-otp',
  body('email').isEmail().withMessage('Valid email is required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;
    const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });
    const expirationTime = Date.now() + parseInt(process.env.OTP_EXPIRATION || 300000);

    OTP_STORE[email] = { otp, expirationTime };

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Verification',
      text: `Your OTP is ${otp}. It is valid for 5 minutes.`,
    };

    try {
      await transporter.sendMail(mailOptions);
      res.status(200).json({ message: 'OTP sent to your email address' });
    } catch (error) {
      console.error('Error sending OTP:', error);
      res.status(500).json({ message: 'Failed to send OTP' });
    }
  }
);

// Endpoint: Verify OTP
app.post(
  '/api/verify-otp',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 characters'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, otp } = req.body;
    const record = OTP_STORE[email];

    if (!record) {
      return res.status(400).json({ message: 'OTP not found. Please request a new one.' });
    }

    if (Date.now() > record.expirationTime) {
      delete OTP_STORE[email];
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    if (record.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP. Please try again.' });
    }

    delete OTP_STORE[email];
    res.status(200).json({ message: 'OTP verified successfully' });
  }
);

// Endpoint: Sign Up
app.post('/api/signup', async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email, and password are required.' });
  }

  try {
    const [existingUser] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'Email is already in use.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [insertResult] = await db.execute(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, role || 'user']
    );

    if (!insertResult.insertId) {
      throw new Error('User insertion failed');
    }

    console.log('New User Inserted with ID:', insertResult.insertId);
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    console.error('Signup Error:', error.message);
    res.status(500).json({ message: 'An error occurred during signup.' });
  }
});

// Endpoint: Sign In
app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(404).json({ message: 'User not found.' });

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials.' });

    const accessToken = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      SECRET_KEY,
      { expiresIn: '7d' }
    );
    const refreshToken = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '14d' });

    res.status(200).json({
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, role: user.role, email: user.email },
    });
  } catch (error) {
    console.error('Signin Error:', error);
    res.status(500).json({ message: 'An error occurred. Please try again.' });
  }
});

// Endpoint: Refresh Token
app.post('/api/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token is required.' });
  }

  try {
    const decoded = jwt.verify(refreshToken, SECRET_KEY);
    const [users] = await db.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);

    if (users.length === 0) {
      return res.status(403).json({ message: 'User not found.' });
    }

    const user = users[0];
    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      SECRET_KEY,
      { expiresIn: '7d' }
    );
    const newRefreshToken = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '14d' });

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error('Refresh Token Error:', error);

    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Refresh token expired.' });
    }

    return res.status(403).json({ message: 'Invalid refresh token.' });
  }
});


// verify user with email
app.post('/api/verify-email', async (req, res) => {
  const { email } = req.body;
  console.log('Received email:', email); // Log received email
  
  try {
    const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    console.log('Query result:', user); // Log query result
    
    if (!user.length) {
      return res.status(404).json({ message: 'Email not found' });
    }
    res.status(200).json({ message: 'Email verified' });
  } catch (error) {
    console.error('Email Verification Error:', error);
    res.status(500).json({ message: 'Failed to verify email' });
  }
});

// Endpoint to fetch pincode details

app.get('/api/pincode/:pincode', async (req, res) => {
  const { pincode } = req.params;

  // Validate PIN code
  if (!/^\d{6}$/.test(pincode)) {
    return res.status(400).json({ error: 'Invalid Pincode. Please provide a 6-digit pincode.' });
  }

  try {
    // Fetch details from India Post API
    const response = await axios.get(`https://api.postalpincode.in/pincode/${pincode}`);

    if (response.data[0]?.Status !== 'Success') {
      return res.status(404).json({ error: 'Pincode not found in the India Post database.' });
    }

    const { PostOffice } = response.data[0];
    if (!PostOffice || PostOffice.length === 0) {
      return res.status(404).json({ error: 'Details not found for the given pincode.' });
    }

    const { State: state, District: district, Taluk: mandal, Name: city } = PostOffice[0] || {};
    if (!state || !district || !city) {
      return res.status(404).json({ error: 'Incomplete details found for the given pincode.' });
    }

    res.status(200).json({
      pincode,
      city,
      state,
      mandal,
      district,
    });
  } catch (error) {
    console.error('Error fetching pincode details:', error.message);
    res.status(500).json({ error: 'Failed to fetch pincode details. Please try again later.' });
  }
});


// reset user password
app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password Reset Error:', error);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});


// Contact Form API Endpoint
app.post('/api/contact', async (req, res) => {
  const { name, email, phone, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).send('Name, email, and message are required');
  }

  try {
    const query = 'INSERT INTO contacts (name, email, phone, message) VALUES (?, ?, ?, ?)';
    const [result] = await db.execute(query, [name, email, phone, message]);
    res.status(200).send('Message saved successfully');
  } catch (error) {
    console.error('Error inserting data:', error);
    res.status(500).send('Failed to save contact data');
  }
});

// Get all products (public endpoint)
app.get('/api/products/shop', async (req, res) => {
  try {
    const [products] = await db.query('SELECT * FROM products'); // Replace with actual query
    res.status(200).json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Failed to fetch products.' });
  }
});

// Fetch Cart Items (with user authentication)
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const [cartItems] = await db.execute(
      'SELECT c.id AS cart_id, c.quantity, p.id AS product_id, p.name, p.price, p.image_url AS image FROM cart c INNER JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
      [req.user.id]
    );
    res.status(200).json(cartItems);
  } catch (error) {
    console.error('Cart Fetch Error:', error);
    res.status(500).json({ message: 'Failed to fetch cart items.' });
  }
});


// Search Products by Name, Description, and Category
app.get('/api/products/search', async (req, res) => {
  const { query } = req.query;

  if (!query) {
    return res.status(400).json({ message: 'Query parameter is required.' });
  }

  try {
    const [products] = await db.execute(
      `
      SELECT *, 
        CASE 
          WHEN name LIKE ? THEN 3
          WHEN description LIKE ? THEN 2
          WHEN category LIKE ? THEN 1
          ELSE 0 
        END AS relevance
      FROM products
      WHERE name LIKE ? OR description LIKE ? OR category LIKE ?
      ORDER BY relevance DESC, name ASC
      `,
      [
        `%${query}%`, // Priority 3: Name match
        `%${query}%`, // Priority 2: Description match
        `%${query}%`, // Priority 1: Category match
        `%${query}%`, // WHERE condition for name
        `%${query}%`, // WHERE condition for description
        `%${query}%`, // WHERE condition for category
      ]
    );

    res.status(200).json(products);
  } catch (error) {
    console.error('Search Error:', error);
    res.status(500).json({ message: 'Failed to fetch search results.' });
  }
});


// suggestions
app.get('/api/products/suggestions', async (req, res) => {
  try {
    // Fetch random products or based on some criteria
    const [products] = await db.execute(
      `SELECT * FROM products 
       WHERE isAvailable = 1 
       ORDER BY RAND() 
       LIMIT 3`
    );

    res.status(200).json(products);
  } catch (error) {
    console.error('Suggestions Error:', error);
    res.status(500).json({ message: 'Failed to fetch suggested products.' });
  }
});


// Get Cart Items
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const [cartItems] = await db.execute(`
      SELECT c.id as cart_id, p.id as product_id, p.name, p.price, p.image_url as image, c.quantity
      FROM cart c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `, [req.user.id]);

    res.status(200).json(cartItems);
  } catch (error) {
    console.error('Fetch Cart Error:', error);
    res.status(500).json({ message: 'Failed to fetch cart items.' });
  }
});

// Add to Cart
app.post('/api/cart', authenticateToken, async (req, res) => {
  const { product_id, quantity } = req.body;

  if (!product_id || !quantity) {
    return res.status(400).json({ message: 'Product ID and quantity are required.' });
  }

  try {
    await db.execute(
      `
      INSERT INTO cart (user_id, product_id, quantity) 
      VALUES (?, ?, ?) 
      ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
      `,
      [req.user.id, product_id, quantity]
    );

    const [cartItems] = await db.execute(
      `
      SELECT 
        c.id, 
        p.name, 
        p.price, 
        p.image_url AS image, 
        c.quantity 
      FROM cart c 
      JOIN products p ON c.product_id = p.id 
      WHERE c.user_id = ?
      `,
      [req.user.id]
    );

    res.status(200).json(cartItems);
  } catch (error) {
    console.error('Add to Cart Error:', error);
    res.status(500).json({ message: 'Failed to add item to cart.' });
  }
});
//patch
app.patch('/api/cart/update', authenticateToken, async (req, res) => {
  const { cart_id, quantity } = req.body;

  if (!cart_id || quantity == null) {
    return res.status(400).json({ message: 'cart_id and quantity are required' });
  }

  try {
    await db.execute('UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?', [
      quantity,
      cart_id,
      req.user.id,
    ]);

    const [cartItems] = await db.execute(`
      SELECT c.id as cart_id, p.id as product_id, p.name, p.price, p.image_url as image, c.quantity
      FROM cart c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `, [req.user.id]);

    res.status(200).json(cartItems);
  } catch (error) {
    console.error('Update Cart Quantity Error:', error);
    res.status(500).json({ message: 'Failed to update cart quantity.' });
  }
});

// Remove from Cart
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(Number(id))) {
    return res.status(400).json({ message: 'Invalid cart ID.' });
  }

  try {
    await db.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', [id, req.user.id]);
    const [cartItems] = await db.execute(`
      SELECT c.id as cart_id, p.id as product_id, p.name, p.price, p.image_url as image, c.quantity
      FROM cart c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `, [req.user.id]);

    res.status(200).json(cartItems);
  } catch (error) {
    console.error('Remove from Cart Error:', error);
    res.status(500).json({ message: 'Failed to remove item from cart.' });
  }
});

// Clear Cart
app.delete('/api/cart', authenticateToken, async (req, res) => {
  try {
    await db.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    res.status(200).json({ message: 'Cart cleared successfully.' });
  } catch (error) {
    console.error('Clear Cart Error:', error);
    res.status(500).json({ message: 'Failed to clear cart.' });
  }
});

// Get Best Sellers (top 6 products)
app.get('/api/products/best-sellers', async (req, res) => {
  try {
    const [products] = await db.execute('SELECT * FROM products LIMIT 6');
    res.status(200).json(products);
  } catch (error) {
    console.error('Failed to fetch best sellers:', error);
    res.status(500).json({ message: 'Failed to fetch best sellers' });
  }
});

//category
app.get('/api/products/category/:category', async (req, res) => {
  const { category } = req.params;
  try {
    const [products] = await db.execute(
      'SELECT * FROM products WHERE category = ?',
      [category]
    );
    res.status(200).json(products);
  } catch (error) {
    console.error('Error fetching products by category:', error);
    res.status(500).json({ message: 'Failed to fetch category products.' });
  }
});

// Fetch New Arrivals
app.get('/api/products/new-arrivals', async (req, res) => {
  try {
    const [products] = await db.query('SELECT * FROM products ORDER BY created_at DESC LIMIT 4');
    res.status(200).json(products);
  } catch (error) {
    console.error('Error fetching new arrivals:', error);
    res.status(500).json({ message: 'Failed to fetch new arrivals.' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [product] = await db.query('SELECT * FROM products WHERE id = ?', [id]);
    if (!product.length) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.status(200).json(product[0]);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Error fetching product' });
  }
});

//Authenticate User Token
function authenticateUserToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract the token from the header

  if (!token) {
    return res.status(401).json({ message: 'Authentication token missing.' }); // Unauthorized
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.error('Token verification error:', err); // Log the error for debugging
      return res.status(403).json({ message: 'Invalid or expired token.' }); // Forbidden
    }

    if (!user || !user.id) {
      return res.status(400).json({ message: 'Invalid user data in token.' }); // Bad Request
    }

    req.user = user; // Attach the decoded user data to the request
    next(); // Proceed to the next middleware or route handler
  });
}



// Get Order by user email
app.get('/api/user-orders', authenticateUserToken, async (req, res) => {
  try {
    const { email } = req.user;

    if (!email) {
      return res.status(400).json({ message: 'Invalid user email.' });
    }

    // Fetch orders for the user
    const [orders] = await db.execute(
      `
      SELECT 
        o.id AS order_id, 
        o.name, 
        o.email, 
        o.phone, 
        o.address, 
        o.total_price, 
        o.status, 
        o.created_at, 
        o.updated_at
      FROM orders o
      WHERE o.email = ?
      ORDER BY o.created_at DESC
      `,
      [email]
    );

    if (!orders.length) {
      return res.status(404).json({ message: 'No orders found for this user.' });
    }

    // Fetch order cart items for the retrieved orders
    const orderIds = orders.map((order) => order.order_id);
    const [orderCartItems] = await db.query(
      `
      SELECT 
        order_id, 
        product_id, 
        name, 
        price, 
        quantity, 
        image 
      FROM order_cart_items 
      WHERE order_id IN (?)
      `,
      [orderIds]
    );

    // Group cart items by order_id
    const cartItemsByOrderId = orderCartItems.reduce((acc, item) => {
      if (!acc[item.order_id]) {
        acc[item.order_id] = [];
      }
      acc[item.order_id].push({
        product_id: item.product_id,
        name: item.name,
        price: item.price,
        quantity: item.quantity,
        image: item.image,
      });
      return acc;
    }, {});

    // Merge orders with cart items and parsed address
    const parsedOrders = orders.map((order) => {
      let parsedAddress;

      // Attempt to parse address
      try {
        parsedAddress = typeof order.address === 'string' ? JSON.parse(order.address) : order.address;
      } catch (error) {
        console.error('Error parsing address:', error, 'Raw address:', order.address);
        parsedAddress = {}; // Fallback to empty object if parsing fails
      }

      return {
        ...order,
        address: parsedAddress,
        cart: cartItemsByOrderId[order.order_id] || [], // Attach cart items
      };
    });

    res.status(200).json(parsedOrders);
  } catch (error) {
    console.error('Fetch Orders Error:', error);
    res.status(500).json({ message: 'Failed to fetch orders.' });
  }
});



// Middleware for admin access
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access forbidden: Admins only.' });
  }
  next();
};
// get all products
app.get('/api/products', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const [products] = await db.query('SELECT * FROM products');
    res.status(200).json(products);
  } catch (error) {
    console.error('Fetch Products Error:', error);
    res.status(500).json({ message: 'Failed to fetch products.' });
  }
});

//add new product to products table
app.post('/api/products', authenticateToken, authorizeAdmin, async (req, res) => {
  const { name, description, price, image_url, category, isAvailable = true, seller_id } = req.body;

  console.log('Incoming Request Body:', { name, description, price, image_url, category, isAvailable, seller_id });

  if (!name || !description || !price || !image_url || !category || !seller_id) {
    console.log('Validation Failed:', { name, description, price, image_url, category, seller_id });
    return res.status(400).json({ message: 'All fields, including seller_id, are required.' });
  }

  const numericPrice = parseFloat(price);
  if (isNaN(numericPrice)) {
    console.log('Invalid Price:', price);
    return res.status(400).json({ message: 'Price must be a valid number.' });
  }

  try {
    const [result] = await db.query(
      'INSERT INTO products (name, description, price, image_url, category, isAvailable, seller_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
      [name, description, numericPrice, image_url, category, isAvailable, seller_id]
    );

    console.log('Product Created:', { 
      id: result.insertId, 
      name, 
      description, 
      numericPrice, 
      category, 
      image_url, 
      isAvailable, 
      seller_id 
    });

    res.status(201).json({ 
      message: 'Product created successfully.', 
      productId: result.insertId 
    });
  } catch (error) {
    console.error('Create Product Error:', error);
    res.status(500).json({ message: 'Failed to create product.' });
  }
});

// get a product by id
app.get('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [products] = await db.execute('SELECT * FROM products WHERE id = ?', [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    res.status(200).json(products[0]);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Failed to fetch product.' });
  }
});


// update product
app.put('/api/products/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, description, image_url, category, isAvailable } = req.body;

  console.log('Incoming Request Body:', { id, name, price, description, image_url, category, isAvailable });

  try {
    // Fetch current product details to get the current price
    const [productRows] = await db.query('SELECT price FROM products WHERE id = ?', [id]);

    if (productRows.length === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    const currentPrice = productRows[0].price; // Get the current price from the database

    // Update the product with the new price and set old_price to the current price
    const [result] = await db.query(
      `UPDATE products 
       SET name = ?, 
           price = ?, 
           old_price = ?, 
           description = ?, 
           image_url = ?, 
           category = ?, 
           isAvailable = ?, 
           updated_at = NOW() 
       WHERE id = ?`,
      [name, price, currentPrice, description, image_url, category, isAvailable, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    console.log('Product Updated:', { id, name, price, old_price: currentPrice });

    res.status(200).json({ message: 'Product updated successfully.' });
  } catch (error) {
    console.error('Update Product Error:', error);
    res.status(500).json({ message: 'Failed to update product.' });
  }
});




// delete a product
app.delete('/api/products/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('DELETE FROM products WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    res.status(200).json({ message: 'Product deleted successfully.' });
  } catch (error) {
    console.error('Delete Product Error:', error);
    res.status(500).json({ message: 'Failed to delete product.' });
  }
});


// POST /api/reviews - Create a new review
app.post('/api/reviews', authenticateUserToken, async (req, res) => {
  const { product_id, product_name, rating, comment } = req.body;
  const user_id = req.user?.id;

  if (!user_id || !product_id || !product_name || !rating || !comment) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const [result] = await db.execute(
      `INSERT INTO reviews (user_id, product_id, product_name, rating, comment, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [user_id, product_id, product_name, rating, comment]
    );

    res.status(201).json({
      id: result.insertId,
      user_id,
      product_id,
      product_name,
      rating,
      comment,
    });
  } catch (error) {
    console.error('Error creating review:', error);
    res.status(500).json({ message: 'Failed to submit review.' });
  }
});

//get sellers
app.get('/api/sellers', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const [sellers] = await db.query('SELECT id, name, email, phone FROM sellers');
    res.status(200).json(sellers);
  } catch (error) {
    console.error('Error fetching sellers:', error);
    res.status(500).json({ message: 'Failed to fetch sellers' });
  }
});

//track-user
app.post('/api/track-user', async (req, res) => {
  try {
    const { email, ipAddress, location, browser, device } = req.body;

    // Insert tracking data into the database
    const query = `
      INSERT INTO user_tracking (email, ip_address, city, region, country, coordinates, browser, device)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
      email,
      ipAddress,
      location.city || null,
      location.region || null,
      location.country || null,
      location.coordinates || null,
      browser,
      device,
    ];

    await db.query(query, values);

    res.status(200).json({ message: 'User tracking data saved successfully' });
  } catch (error) {
    console.error('Error saving tracking data:', error);
    res.status(500).json({ message: 'Failed to save tracking data' });
  }
});


// Order Endpoint
app.post('/api/orders', async (req, res) => {
  const { name, email, phone, address, cart } = req.body;

  // Validate request payload
  if (!name || !email || !phone || !address || !cart || cart.length === 0) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    // Calculate total_price
    const total_price = cart.reduce((total, item) => {
      return total + (item.quantity * item.price);
    }, 0);

    // Insert order into the database
    const [result] = await db.query(
      `INSERT INTO orders (name, email, phone, address, cart, total_price, status, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
      [name, email, phone, JSON.stringify(address), JSON.stringify(cart), total_price, 'Pending Payment']
    );

    res.status(201).json({ message: 'Order created successfully', orderId: result.insertId });
  } catch (error) {
    console.error('Order Creation Error:', error);
    res.status(500).json({ message: 'Failed to create order.' });
  }
});

// Fetch orders along with order_cart_items
app.get('/api/orders', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    // Fetch orders and their associated cart items from the database
    const [orders] = await db.query(`
      SELECT 
        o.id AS order_id,
        o.name,
        o.email,
        o.phone,
        o.address, -- Address remains as plain text
        o.status,
        o.total_price,
        o.created_at,
        ci.product_id,
        ci.name AS product_name,
        ci.price AS product_price,
        ci.quantity,
        ci.image AS product_image
      FROM orders o
      LEFT JOIN order_cart_items ci ON o.id = ci.order_id
      ORDER BY o.created_at DESC -- Load orders in descending order by created_at
    `);

    // Group orders and their cart items
    const ordersWithItems = orders.reduce((acc, row) => {
      const { 
        order_id,
        name,
        email,
        phone,
        address,
        status,
        total_price,
        created_at,
        product_id,
        product_name,
        product_price,
        quantity,
        product_image,
      } = row;

      // Check if the order already exists in the accumulator
      if (!acc[order_id]) {
        acc[order_id] = {
          id: order_id,
          name,
          email,
          phone,
          address,
          status,
          total_price,
          created_at,
          items: [], // Initialize items array for the order
        };
      }

      // Add the cart item to the order's items array if it exists
      if (product_id) {
        acc[order_id].items.push({
          product_id,
          product_name,
          product_price,
          quantity,
          product_image,
        });
      }

      return acc;
    }, {});

    // Convert the grouped orders object to an array
    const parsedOrders = Object.values(ordersWithItems);

    // Respond with the parsed orders
    res.status(200).json(parsedOrders);
  } catch (error) {
    console.error('Failed to fetch orders:', error);
    res.status(500).json({ message: 'Failed to fetch orders.' });
  }
});




// Update Order Status Endpoint
app.put('/api/orders/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params; // Order ID from URL parameters
  const { status } = req.body; // New status from request body

  try {
    // Define valid statuses
    const validStatuses = ['Pending Payment', 'Payment Received', 'Shipped', 'Delivered', 'Cancelled'];
    
    // Check if the provided status is valid
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status value.' });
    }

    // Update the order status in the database
    const [result] = await db.query('UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?', [status, id]);

    // If no rows were affected, the order ID does not exist
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    // Fetch the updated order to return it in the response
    const [updatedOrder] = await db.query(
      `SELECT 
        id,
        name,
        email,
        phone,
        address,
        cart,
        status,
        total_price,
        created_at,
        updated_at
       FROM orders
       WHERE id = ?`,
      [id]
    );

    if (!updatedOrder.length) {
      return res.status(404).json({ message: 'Order not found after update.' });
    }

    // Parse the `cart` field if it's stored as a string in the database
    const order = updatedOrder[0];
    if (order.cart && typeof order.cart === 'string') {
      try {
        order.cart = JSON.parse(order.cart);
      } catch (error) {
        console.error(`Error parsing cart for Order ID: ${id}`, error);
        order.cart = []; // Fallback to an empty array
      }
    }

    // Respond with the updated order
    res.status(200).json(order);
  } catch (error) {
    console.error('Failed to update order status:', error);
    res.status(500).json({ message: 'Failed to update order status.' });
  }
});



// Razorpay Configuration
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY,
  key_secret: process.env.RAZORPAY_SECRET,
});

// Endpoint: Create Razorpay Order
app.post('/api/create-order', async (req, res) => {
  const { amount, currency } = req.body;

  if (!amount || !currency) {
    return res.status(400).json({ message: 'Amount and currency are required' });
  }

  try {
    const options = {
      amount: amount * 100, // Convert to paise
      currency,
      receipt: `receipt_${Date.now()}`, // Unique receipt ID
    };

    const order = await razorpay.orders.create(options);
    res.status(201).json(order);
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    res.status(500).json({ message: 'Failed to create order' });
  }
});

// Endpoint: Verify Razorpay Payment
app.post('/api/verify-payment', async (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
    return res.status(400).json({
      success: false,
      message: 'razorpay_payment_id, razorpay_order_id, and razorpay_signature are required.',
    });
  }

  try {
    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: 'Payment verification failed: Signature mismatch.',
      });
    }

    res.json({
      success: true,
      message: 'Payment verified successfully.',
      data: { razorpay_payment_id, razorpay_order_id },
    });
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ success: false, message: 'Internal server error while verifying payment.' });
  }
});

// Endpoint: Create User Order
app.post('/api/create-user-order', authenticateToken, async (req, res) => {
  const { name, email, phone, address, cart, total_price, razorpay_order_id, payment_id } = req.body;

  //console.log('=== Incoming Request Body ===', req.body);

  if (!name || !email || !phone || !address || !cart || !total_price || !razorpay_order_id || !payment_id) {
    console.error('Missing required fields:', { name, email, phone, address, cart, total_price, razorpay_order_id, payment_id });
    return res.status(400).json({ message: 'All fields are required.' });
  }

  let parsedCart;
  let parsedAddress;

  try {
    //console.log('Parsing cart and address...');
    parsedCart = Array.isArray(cart) ? cart : JSON.parse(cart);
    parsedAddress = typeof address === 'object' ? address : JSON.parse(address);
    //console.log('Parsed Cart:', parsedCart);
    //console.log('Parsed Address:', parsedAddress);
  } catch (error) {
    console.error('Error parsing cart or address:', error);
    return res.status(400).json({ message: 'Invalid cart or address format.' });
  }

  const userId = req.user?.id;

  if (!userId) {
    console.error('Unauthorized access: Missing user ID');
    return res.status(401).json({ message: 'Unauthorized: User ID is required.' });
  }

  if (parsedCart.length === 0) {
    console.error('Cart is empty. No items found.');
    return res.status(400).json({ message: 'Cart must contain at least one product.' });
  }

  let orderId;

  try {
    //console.log('Starting database transaction...');
    await db.query('START TRANSACTION');

    // Insert into orders table
    const orderQuery = `
      INSERT INTO orders (name, email, phone, address, total_price, razorpay_order_id, payment_id, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    `;
    const orderValues = [
      name,
      email,
      phone,
      JSON.stringify(parsedAddress), // Serialize address as JSON string
      total_price,
      razorpay_order_id,
      payment_id,
      'Payment Received',
    ];

   // console.log('Executing Order Query:', orderQuery, 'With Values:', orderValues);

    const [orderResult] = await db.query(orderQuery, orderValues);

    if (!orderResult.insertId) {
      throw new Error('Order insertion failed.');
    }

    orderId = orderResult.insertId;
    //console.log('Order inserted with ID:', orderId);

    // Insert cart items into order_cart_items table
    const cartItemsQuery = `
      INSERT INTO order_cart_items (order_id, product_id, name, price, quantity, image, created_at, updated_at)
      VALUES ?
    `;
    const cartItemsValues = parsedCart.map((item) => [
      orderId,
      item.product_id,
      item.name,
      parseFloat(item.price),
      item.quantity,
      item.image,
      new Date(),
      new Date(),
    ]);

    //console.log('Executing Cart Items Query:', cartItemsQuery);
    //console.log('With Values:', cartItemsValues);

    await db.query(cartItemsQuery, [cartItemsValues]);

    //console.log('Cart items inserted for order ID:', orderId);

    // Commit the transaction
    await db.query('COMMIT');
    //console.log('Transaction committed successfully.');

    // Separate email sending for sellers and users
    sendEmailsToSellers(parsedCart, orderId, {
      name,
      email,
      phone,
      address: parsedAddress,
      razorpay_order_id,
    });

    sendEmailToUser(orderId, {
      name,
      email,
      phone,
      address: parsedAddress,
      cart: parsedCart,
      total_price,
      razorpay_order_id,
    });

    // Clear the user's cart
    const deleteCartQuery = `DELETE FROM cart WHERE user_id = ?`;
    //console.log(`Clearing cart for user ID: ${userId} with query: ${deleteCartQuery}`);
    await db.query(deleteCartQuery, [userId]);

    res.status(201).json({ message: 'Order created successfully, cart cleared, and emails sent.' });
  } catch (error) {
    console.error('Error during order creation:', error);
    await db.query('ROLLBACK');
    res.status(500).json({ message: 'Failed to create order. Please try again later.' });
  }
});

// Function to send emails to sellers
async function sendEmailsToSellers(cart, orderId, orderDetails) {
  try {
    const productIds = cart.map((item) => item.product_id);
    const sellerProductsQuery = `
      SELECT sellers.email AS seller_email, sellers.id AS seller_id, products.id AS product_id, products.name AS product_name, products.price AS product_price
      FROM sellers
      INNER JOIN products ON products.seller_id = sellers.id
      WHERE products.id IN (?)
    `;

    //console.log('Fetching seller products with query:', sellerProductsQuery);
    const [sellerProductRows] = await db.query(sellerProductsQuery, [productIds]);

    //console.log('Seller Products Retrieved:', sellerProductRows);

    const productsBySeller = sellerProductRows.reduce((acc, row) => {
      if (!acc[row.seller_id]) {
        acc[row.seller_id] = { email: row.seller_email, products: [] };
      }
      acc[row.seller_id].products.push({
        id: row.product_id,
        name: row.product_name,
        price: row.product_price,
        quantity: cart.find((item) => item.product_id === row.product_id)?.quantity || 1,
      });
      return acc;
    }, {});

    //console.log('Grouped Products by Seller:', productsBySeller);

    await Promise.all(
      Object.values(productsBySeller).map(async (sellerData) => {
        const sellerOrderDetails = {
          ...orderDetails,
          cart: sellerData.products,
          total_price: sellerData.products.reduce((sum, product) => sum + product.price * product.quantity, 0),
        };

        //console.log(`Sending email to seller: ${sellerData.email}`);
        await sendEmailWithPDF(sellerData.email, sellerOrderDetails);
      })
    );
  } catch (error) {
    console.error('Error while sending emails to sellers:', error);
  }
}

// Function to send an email to the user
async function sendEmailToUser(orderId, orderDetails) {
  try {
    //console.log('Sending email with order details to user...');
    await sendOrderEmailToUser(orderDetails);
    //console.log('User email sent successfully.');
  } catch (error) {
    console.error('Failed to send email to user:', error);
  }
}

// Email Send Function
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendEmailWithPDF(sellerEmail, orderDetails) {
  const pdfBytes = await generatePDF(orderDetails);

  const date = new Date();
  const formattedDate = `${date.getFullYear()}-${(date.getMonth() + 1)
    .toString()
    .padStart(2, '0')}-${date.getDate().toString().padStart(2, '0')}`;

  const sanitizedUserName = orderDetails.name.replace(/[^a-zA-Z0-9]/g, '_');

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: sellerEmail,
    subject: `New Order: ${orderDetails.name}`,
    text: 'A new order has been placed. Please find the attached details.',
    attachments: [
      {
        filename: `order_${sanitizedUserName}_${formattedDate}.pdf`,
        content: pdfBytes,
        contentType: 'application/pdf',
      },
    ],
  };

  return transporter.sendMail(mailOptions);
}

// PDF Generation Function
async function generatePDF(orderDetails) {
  const pdfDoc = await PDFDocument.create();
  pdfDoc.registerFontkit(fontkit);

  const page = pdfDoc.addPage([600, 850]);
  const margin = 50;
  let yOffset = 800;

  const logoUrl = 'https://lara-orders.s3.ap-south-1.amazonaws.com/images/logo-transparent-png.png';
  const fontUrl = 'https://lara-orders.s3.ap-south-1.amazonaws.com/fonts/Roboto-Regular.ttf';
  const fontBytes = await fetch(fontUrl).then((res) => res.arrayBuffer());
  const customFont = await pdfDoc.embedFont(fontBytes);

  const date = new Date();
  const orderPlacedDate = date.toLocaleString();

  // Add Logo
  try {
    const logoBytes = await fetch(logoUrl).then((res) => res.arrayBuffer());
    const logoImage = await pdfDoc.embedPng(logoBytes);
    const logoWidth = 120;
    const logoHeight = logoImage.height / (logoImage.width / logoWidth);
    const logoX = (600 - logoWidth) / 2;

    page.drawImage(logoImage, {
      x: logoX,
      y: yOffset - 50,
      width: logoWidth,
      height: logoHeight,
    });

    yOffset -= 100;
  } catch (err) {
    console.error('Logo Fetch Error:', err);
    yOffset -= 20;
  }

  // Order Title
  page.drawText('Order Receipt', {
    x: margin,
    y: yOffset,
    size: 20,
    font: customFont,
    color: rgb(0, 0.3, 0.6),
  });
  yOffset -= 40;

  // Order Info
  page.drawText(`Order ID: ${orderDetails.razorpay_order_id}`, {
    x: margin,
    y: yOffset,
    size: 12,
    font: customFont,
    color: rgb(0.5, 0.5, 0.5),
  });
  page.drawText(`Placed on: ${orderPlacedDate}`, {
    x: 400,
    y: yOffset,
    size: 12,
    font: customFont,
    color: rgb(0.5, 0.5, 0.5),
  });
  yOffset -= 30;

  // Customer Details
  page.drawText('Customer Details', {
    x: margin,
    y: yOffset,
    size: 14,
    font: customFont,
    color: rgb(0, 0, 0),
  });
  yOffset -= 20;

  page.drawText(`Name: ${orderDetails.name}`, { x: margin, y: yOffset, size: 12, font: customFont });
  page.drawText(`Email: ${orderDetails.email}`, { x: margin, y: yOffset - 20, size: 12, font: customFont });
  page.drawText(`Phone: ${orderDetails.phone}`, { x: margin, y: yOffset - 40, size: 12, font: customFont });
  yOffset -= 80;

  // Address Section
  page.drawText('Shipping Address', {
    x: margin,
    y: yOffset,
    size: 14,
    font: customFont,
    color: rgb(0, 0, 0),
  });
  yOffset -= 20;

  const formattedAddress = `${orderDetails.address.addressLane}, ${orderDetails.address.city}, ${orderDetails.address.mandal}, ${orderDetails.address.district}, ${orderDetails.address.state} - ${orderDetails.address.pinCode}`;
  formattedAddress.split(',').forEach((line) => {
    page.drawText(line.trim(), { x: margin, y: yOffset, size: 12, font: customFont });
    yOffset -= 20;
  });
  yOffset -= 40;

  // Order Details
  page.drawText('Order Details', {
    x: margin,
    y: yOffset,
    size: 14,
    font: customFont,
    color: rgb(0, 0, 0),
  });
  yOffset -= 20;

  // Cart Headers
  page.drawText('Item', { x: margin, y: yOffset, size: 12, font: customFont });
  page.drawText('Qty', { x: 350, y: yOffset, size: 12, font: customFont });
  page.drawText('Price', { x: 450, y: yOffset, size: 12, font: customFont });
  page.drawText('Total', { x: 500, y: yOffset, size: 12, font: customFont });
  yOffset -= 20;

  // Cart Items
  orderDetails.cart.forEach((item, index) => {
    const quantity = item.quantity || 0;
    const price = parseFloat(item.price) || 0;
    const totalItemPrice = quantity * price;

    page.drawText(`${index + 1}. ${item.name}`, { x: margin, y: yOffset, size: 12, font: customFont });
    page.drawText(`${quantity}`, { x: 350, y: yOffset, size: 12, font: customFont });
    page.drawText(`₹${price.toFixed(2)}`, { x: 450, y: yOffset, size: 12, font: customFont });
    page.drawText(`₹${totalItemPrice.toFixed(2)}`, { x: 500, y: yOffset, size: 12, font: customFont });
    yOffset -= 20;
  });

  yOffset -= 30;

  // Total
  const totalPrice = parseFloat(orderDetails.total_price) || 0;
  page.drawText(`Sub Total: ₹${totalPrice.toFixed(2)}`, {
    x: margin,
    y: yOffset,
    size: 16,
    font: customFont,
    color: rgb(0, 0.5, 0),
  });

  yOffset -= 50;

  // Footer Note
  page.drawText('Thank you for your purchase!', {
    x: margin,
    y: yOffset,
    size: 12,
    font: customFont,
    color: rgb(0, 0.3, 0.6),
  });

  return await pdfDoc.save();
}

// Function to Send Email with User's Order Details
export async function sendOrderEmailToUser(orderDetails) {
  try {
    const pdfBytes = await generateUserPDF(orderDetails);

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: orderDetails.email,
      subject: 'Your Order Receipt',
      html: `
        <p>Dear ${orderDetails.name},</p>
        <p>Thank you for your purchase! Attached is your order receipt.</p>
        <p><strong>Order Summary:</strong></p>
        <ul>
          ${orderDetails.cart
            .map(
              (item) => `
            <li>
              <strong>${item.name}</strong> - Qty: ${item.quantity} - ₹${(
                item.quantity * parseFloat(item.price)
              ).toFixed(2)}
            </li>`
            )
            .join('')}
        </ul>
        <p><strong>Total Amount:</strong> ₹${parseFloat(orderDetails.total_price).toFixed(2)}</p>
        <p>We hope to serve you again soon!</p>
        <p>Best regards,<br>Lara Jewels</p>
      `,
      attachments: [
        {
          filename: `Order_Receipt_${orderDetails.name.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`,
          content: pdfBytes,
          contentType: 'application/pdf',
        },
      ],
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully: ', info.response);
    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send order receipt email.');
  }
}

// Function to Generate User PDF for Order Receipt
async function generateUserPDF(orderDetails) {
  const pdfDoc = await PDFDocument.create();

  // Register fontkit
  pdfDoc.registerFontkit(fontkit);

  const page = pdfDoc.addPage([600, 850]);
  const margin = 50;
  let yOffset = 800;

  const logoUrl = 'https://lara-orders.s3.ap-south-1.amazonaws.com/images/logo-transparent-png.png';
  const fontUrl = 'https://lara-orders.s3.ap-south-1.amazonaws.com/fonts/Roboto-Regular.ttf';
  const fontBytes = await fetch(fontUrl).then((res) => res.arrayBuffer());
  const customFont = await pdfDoc.embedFont(fontBytes);

  const date = new Date();
  const orderPlacedDate = date.toLocaleString();

  // Add Logo
  try {
    const logoBytes = await fetch(logoUrl).then((res) => res.arrayBuffer());
    const logoImage = await pdfDoc.embedPng(logoBytes);
    const logoWidth = 120;
    const logoHeight = logoImage.height / (logoImage.width / logoWidth);
    const logoX = (600 - logoWidth) / 2;

    page.drawImage(logoImage, {
      x: logoX,
      y: yOffset - 50,
      width: logoWidth,
      height: logoHeight,
    });

    yOffset -= 100;
  } catch (err) {
    console.error('Logo Fetch Error:', err);
    yOffset -= 20;
  }

  // Add Order Title
  page.drawText('Order Receipt', {
    x: margin,
    y: yOffset,
    size: 20,
    font: customFont,
    color: rgb(0, 0.3, 0.6),
  });
  yOffset -= 40;

  // Add Order Date and ID
  page.drawText(`Order ID: ${orderDetails.razorpay_order_id}`, {
    x: margin,
    y: yOffset,
    size: 12,
    font: customFont,
    color: rgb(0.5, 0.5, 0.5),
  });
  page.drawText(`Placed on: ${orderPlacedDate}`, {
    x: 400,
    y: yOffset,
    size: 12,
    font: customFont,
    color: rgb(0.5, 0.5, 0.5),
  });
  yOffset -= 30;

  // Customer Details Section
  page.drawText('Customer Details', {
    x: margin,
    y: yOffset,
    size: 14,
    font: customFont,
    color: rgb(0, 0, 0),
  });
  yOffset -= 20;

  page.drawText(`Name: ${orderDetails.name}`, { x: margin, y: yOffset, size: 12, font: customFont });
  page.drawText(`Email: ${orderDetails.email}`, { x: margin, y: yOffset - 20, size: 12, font: customFont });
  page.drawText(`Phone: ${orderDetails.phone}`, { x: margin, y: yOffset - 40, size: 12, font: customFont });
  yOffset -= 80;

  // Shipping Address Section
  page.drawText('Shipping Address', {
    x: margin,
    y: yOffset,
    size: 14,
    font: customFont,
    color: rgb(0, 0, 0),
  });
  yOffset -= 20;

  const formattedAddress = `${orderDetails.address.addressLane}, ${orderDetails.address.city}, ${orderDetails.address.mandal}, ${orderDetails.address.district}, ${orderDetails.address.state} - ${orderDetails.address.pinCode}`;
  formattedAddress.split(',').forEach((line) => {
    page.drawText(line.trim(), { x: margin, y: yOffset, size: 12, font: customFont });
    yOffset -= 20;
  });
  yOffset -= 40;

  // Order Details Section
  page.drawText('Order Details', {
    x: margin,
    y: yOffset,
    size: 14,
    font: customFont,
    color: rgb(0, 0, 0),
  });
  yOffset -= 20;

  // Cart Headers
  page.drawText('Item', { x: margin, y: yOffset, size: 12, font: customFont });
  page.drawText('Qty', { x: 350, y: yOffset, size: 12, font: customFont });
  page.drawText('Price', { x: 450, y: yOffset, size: 12, font: customFont });
  page.drawText('Total', { x: 500, y: yOffset, size: 12, font: customFont });
  yOffset -= 20;

  // Cart Items
  orderDetails.cart.forEach((item, index) => {
    const quantity = item.quantity || 0;
    const price = parseFloat(item.price) || 0;
    const totalItemPrice = quantity * price;

    page.drawText(`${index + 1}. ${item.name}`, { x: margin, y: yOffset, size: 12, font: customFont });
    page.drawText(`${quantity}`, { x: 350, y: yOffset, size: 12, font: customFont });
    page.drawText(`₹${price.toFixed(2)}`, { x: 450, y: yOffset, size: 12, font: customFont });
    page.drawText(`₹${totalItemPrice.toFixed(2)}`, { x: 500, y: yOffset, size: 12, font: customFont });
    yOffset -= 20;
  });

  yOffset -= 30;

  // Total Price Section
  const totalPrice = parseFloat(orderDetails.total_price) || 0;
  page.drawText(`Total Amount: ₹${totalPrice.toFixed(2)}`, {
    x: margin,
    y: yOffset,
    size: 16,
    font: customFont,
    color: rgb(0, 0.5, 0),
  });

  yOffset -= 50;

  // Footer Note
  page.drawText('Thank you for your purchase! Your order will be shipped within 2 business days.', {
    x: margin,
    y: yOffset,
    size: 12,
    font: customFont,
    color: rgb(0, 0.3, 0.6),
  });

  // Save PDF Bytes
  return await pdfDoc.save();
}



// Start Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
