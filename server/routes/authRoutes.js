// Step 1️⃣: Import Express and controller functions
import express from 'express';
import { isAuthenticated, login, logout, register, sendVerifyOtp, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';

// Step 2️⃣: Create a new Router instance
const authRouter = express.Router();

// Step 3️⃣: Define route for user registration
// 📌 Route: POST /api/auth/register
// 📝 Public route for new user registration
authRouter.post('/register', register);

// Step 4️⃣: Define route for user login
// 📌 Route: POST /api/auth/login
// 📝 Public route for logging in and receiving JWT token
authRouter.post('/login', login);

// Step 5️⃣: Define route for user logout
// 📌 Route: POST /api/auth/logout
// 📝 Public or protected route depending on implementation (clears cookie/token)
authRouter.post('/logout', logout);

// Step 6️⃣: Define route to send verification OTP
// 📌 Route: POST /api/auth/send-verify-otp
// 🔐 Protected route — requires valid token to send OTP
authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp);

// Step 7️⃣: Define route to verify account using OTP
// 📌 Route: POST /api/auth/verify-account
// 🔐 Protected route — requires token and valid OTP
authRouter.post('/verify-account', userAuth, verifyEmail);

// Step 8️⃣: Define route to check authentication status
// 📌 Route: POST /api/auth/is-auth
// 🔐 Protected route — used to check if the user's token is valid
// 🛡️ If token is valid, the user is considered authenticated and can access protected routes
authRouter.post('/is-auth', userAuth, isAuthenticated);

// Step 9️⃣: Export the router to be used in the main app
export default authRouter;

// Type	       How You Know	Example from Your Code
// Public	   🚫 No userAuth middleware used	                 /register, /login, /logout
// Protected   ✅ Has userAuth middleware before controller	    /send-verify-otp, /verify-account
