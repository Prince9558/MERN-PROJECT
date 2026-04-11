require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const authRoutes = require('./src/routes/authRoutes');
const linksRoutes = require('./src/routes/linksRoutes');
const userRoutes = require('./src/routes/userRoutes');
const paymentRoutes = require('./src/routes/paymentRoutes');

const app = express();

// Middleware
app.use((req, res, next) => {
  if (req.originalUrl.startsWith('/payments/webhook')) {
    return next();
  }
  express.json()(req, res, next);
});

app.use(cookieParser());

const allowedOrigins = [
  'http://localhost:3000',
  'https://singular-gingersnap-4706d5.netlify.app',
  'https://visionary-banoffee-3f22a8.netlify.app',
  'https://affiliate-plus-plus.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use('/auth', authRoutes);
app.use('/links', linksRoutes);
app.use('/users', userRoutes);
app.use('/payments', paymentRoutes);

// 🔥 IMPORTANT FIX STARTS HERE

const PORT = process.env.PORT || 5001;

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB Connected');

    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });

  })
  .catch((error) => {
    console.log('❌ DB Connection Error:', error);
  });