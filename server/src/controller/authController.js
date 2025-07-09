const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Users = require('../model/Users');
const { OAuth2Client } = require('google-auth-library');
const { validationResult } = require('express-validator');
const Razorpay = require('razorpay');

// https://www.uuidgenerator.net/
const secret = process.env.JWT_SECRET;

// Initialize Razorpay instance (put your env variables in .env)
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const authController = {
  login: async (request, response) => {
    try {
      const errors = validationResult(request);
      if (!errors.isEmpty()) {
        return response.status(401).json({ errors: errors.array() });
      }

      const { username, password } = request.body;

      const data = await Users.findOne({ email: username });
      if (!data) {
        return response
          .status(401)
          .json({ message: 'Invalid credentials ' });
      }

      const isMatch = await bcrypt.compare(password, data.password);
      if (!isMatch) {
        return response
          .status(401)
          .json({ message: 'Invalid credentials ' });
      }

      const user = {
        id: data._id,
        name: data.name,
        email: data.email,
        role: data.role ? data.role : 'admin',
        adminId: data.adminId,
        credits: data.credits,
        subscription: data.subscription,
      };

      const token = jwt.sign(user, secret, { expiresIn: '1h' });
      response.cookie('jwtToken', token, {
        httpOnly: true,
        secure: true,
        domain: 'localhost',
        path: '/',
      });
      response.json({ user: user, message: 'User authenticated' });
    } catch (error) {
      console.log(error);
      response.status(500).json({ error: 'Internal server error' });
    }
  },

  logout: (request, response) => {
    response.clearCookie('jwtToken');
    response.json({ message: 'Logout successful' });
  },

  isUserLoggedIn: async (request, response) => {
    const token = request.cookies.jwtToken;

    if (!token) {
      return response
        .status(401)
        .json({ message: 'Unauthorized access' });
    }

    jwt.verify(token, secret, async (error, user) => {
      if (error) {
        return response
          .status(401)
          .json({ message: 'Unauthorized access' });
      } else {
        const latestUserDetails = await Users.findById({
          _id: user.id,
        });
        response.json({
          message: 'User is logged in',
          user: latestUserDetails,
        });
      }
    });
  },

  register: async (request, response) => {
    try {
      const { username, password, name } = request.body;

      const data = await Users.findOne({ email: username });
      if (data) {
        return response
          .status(401)
          .json({
            message:
              'Account already exists with the given email',
          });
      }

      const encryptedPassword = await bcrypt.hash(password, 10);

      const user = new Users({
        email: username,
        password: encryptedPassword,
        name: name,
        role: 'admin',
      });
      await user.save();

      const userDetails = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        credits: user.credits,
      };

      const token = jwt.sign(userDetails, secret, {
        expiresIn: '1h',
      });

      response.cookie('jwtToken', token, {
        httpOnly: true,
        secure: true,
        domain: 'localhost',
        path: '/',
      });
      response.json({
        message: 'User registered',
        user: userDetails,
      });
    } catch (error) {
      console.log(error);
      return response
        .status(500)
        .json({ error: 'Internal Server Error' });
    }
  },

  googleAuth: async (request, response) => {
    try {
      const { idToken } = request.body;
      if (!idToken) {
        return response
          .status(401)
          .json({ message: 'Invalid request' });
      }

      const googleClient = new OAuth2Client(
        process.env.GOOGLE_CLIENT_ID
      );
      const googleResponse =
        await googleClient.verifyIdToken({
          idToken: idToken,
          audience: process.env.GOOGLE_CLIENT_ID,
        });

      const payload = googleResponse.getPayload();
      const { sub: googleId, name, email } = payload;

      let data = await Users.findOne({ email: email });
      if (!data) {
        data = new Users({
          email: email,
          name: name,
          isGoogleUser: true,
          googleId: googleId,
          role: 'admin',
        });
        await data.save();
      }

      const user = {
        id: data._id ? data._id : googleId,
        username: email,
        name: name,
        role: data.role ? data.role : 'admin',
      };

      const token = jwt.sign(user, secret, {
        expiresIn: '1h',
      });
      response.cookie('jwtToken', token, {
        httpOnly: true,
        secure: true,
        domain: 'localhost',
        path: '/',
      });
      response.json({
        user: user,
        message: 'User authenticated',
      });
    } catch (error) {
      console.log(error);
      return response
        .status(500)
        .json({ message: 'Internal server error' });
    }
  },
};

module.exports = authController;
