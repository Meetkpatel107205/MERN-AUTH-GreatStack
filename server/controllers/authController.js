// Importing bcryptjs library to hash (encrypt) passwords
import bcrypt from "bcryptjs";

// Importing jsonwebtoken to generate secure tokens for user sessions
import jwt from "jsonwebtoken";

// Importing the user model which interacts with the MongoDB database
import userModel from "../models/userModel.js";

// Import the configured Nodemailer transporter instance for sending emails
import transporter from "../config/nodemailer.js";

import {
  EMAIL_VERIFY_TEMPLATE,
  PASSWORD_RESET_TEMPLATE,
} from "../config/emailTemplates.js";

// Register controller function
export const register = async (req, res) => {
  // 📨 Step 1: Extract user input from request body
  const { name, email, password } = req.body;

  // ❗ Step 2: Check if any field is missing
  if (!name || !email || !password) {
    return res.json({
      success: false,
      message: "Missing Details", // Return error if any required field is empty
    });
  }

  try {
    // 🔍 Step 3: Check if user already exists using email
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      // ❌ Step 4: If user is found, block registration
      return res.json({
        success: false,
        message: "User already exists",
      });
    }

    // 🔐 Step 5: Hash the password securely using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10); // 10 = salt rounds

    // 🏗️ Step 6: Create a new user object
    const user = new userModel({
      name: name,
      email: email,
      password: hashedPassword, // Store hashed password only
    });

    // 💾 Step 7: Save the new user to the database
    await user.save();

    // 🔏 Step 8: Generate JWT token with user ID as payload
    const token = jwt.sign(
      { id: user._id }, // user ID goes inside token
      process.env.JWT_SECRET, // secret key from .env
      { expiresIn: "7d" } // token valid for 7 days
    );

    // 🍪 Step 9: Send token in HTTP-only cookie (browser stores it)
    res.cookie("token", token, {
      httpOnly: true, // cookie can't be accessed by JS (prevents XSS)
      secure: process.env.NODE_ENV === "production", // use secure only on HTTPS (prod)
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", // cross-site handling
      maxAge: 7 * 24 * 60 * 60 * 1000, // valid for 7 days (in ms)
    });

    // Configure the welcome email (plain text only)
    const mailOptions = {
      from: process.env.SENDER_EMAIL, // Sender email address (from environment variable)
      to: email, // Recipient's email address
      subject: "Welcome to Authentication Website", // Subject line of the email
      text: `Hello,
        
        Welcome to the Authentication Website! Your account has been successfully created with the email ID: ${email}.
        
        We're excited to have you with us. If you have any questions, just reply to this email.
        
        Best regards,  
        The Auth Team`, // Plain text body of the email
    };

    await transporter.sendMail(mailOptions);

    // ✅ Step 10: Send success response to frontend
    return res.json({
      success: true,
    });
  } catch (err) {
    // ❌ Step 11: Handle and return server error
    res.json({
      success: false,
      message: err.message,
    });
  }
};

// Login controller function
export const login = async (req, res) => {
  // 📨 Step 1: Get user input from request body
  const { email, password } = req.body;

  // ❗ Step 2: Check if both fields are provided
  if (!email || !password) {
    return res.json({
      success: false,
      message: "Email and password are required", // Show error if any field is missing
    });
  }

  try {
    // 🔍 Step 3: Check if user exists in database by email
    const user = await userModel.findOne({ email });

    // ❌ If user not found, return error
    if (!user) {
      return res.json({
        success: false,
        message: "Invalid email",
      });
    }

    // 🔑 Step 4: Compare entered password with hashed password from DB
    const isMatch = await bcrypt.compare(password, user.password);

    // ❌ If passwords don't match, return error
    if (!isMatch) {
      return res.json({
        success: false,
        message: "Invalid password",
      });
    }

    // 🔏 Step 5: Generate JWT token with user ID as payload
    const token = jwt.sign(
      { id: user._id }, // user ID as token payload
      process.env.JWT_SECRET, // secret key stored in .env file
      { expiresIn: "7d" } // token expires in 7 days
    );

    // 🍪 Step 6: Store token in HTTP-only cookie for authentication
    res.cookie("token", token, {
      httpOnly: true, // JavaScript in browser cannot access it (protects from XSS)
      secure: process.env.NODE_ENV === "production", // use HTTPS in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", // controls cross-origin cookie behavior
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
    });

    // ✅ Step 7: Return success response
    return res.json({
      success: true,
    });
  } catch (error) {
    // ❌ Step 8: Catch any server error and return it
    return res.json({
      success: false,
      message: error.message,
    });
  }
};

// Logout controller function
export const logout = async (req, res) => {
  try {
    // 🚫 Step 1: Clear the token cookie to log the user out
    res.clearCookie("token", {
      httpOnly: true, // cookie can't be accessed via JavaScript
      secure: process.env.NODE_ENV === "production", // use HTTPS in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", // handle cross-site
    });

    // ✅ Step 2: Send successful logout response
    return res.json({
      success: true,
      message: "Logged Out",
    });
  } catch (error) {
    // ❌ Step 3: Handle and return server error
    return res.json({
      success: false,
      message: error.message,
    });
  }
};

// 🚀 Controller to send account verification OTP to the user's email
export const sendVerifyOtp = async (req, res) => {
  try {
    // Prefer authenticated ID over body
    const userId = req.userId || req.body.userId;

    // 🔍 Fetch user from the database
    const user = await userModel.findById(userId);

    // ✅ If already verified, return early
    if (user.isAccountVerified) {
      return res.json({
        success: false,
        message: "Account already verified",
      });
    }

    // 🔢 Generate a 6-digit OTP (e.g., 123456)
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // 🕒 Set OTP and its expiry time (24 hours from now)
    user.verifyOtp = otp;
    user.verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000;

    // 💾 Save the OTP to the database
    await user.save();

    // ✉️ Compose the OTP email in plain text format
    const mailOptions = {
      from: process.env.SENDER_EMAIL, // Sender's email address (from .env)
      to: user.email, // Recipient's email address (user's registered email)
      subject: "Account Verification OTP", // Subject line

      // Plain-text body (for email clients without HTML support)
      // text: `Hello,

      // Thank you for registering on the Authentication Website!

      // Your one-time password (OTP) for account verification is: ${otp}

      // Please enter this OTP in the app to verify your account. This OTP is valid for 24 hours.

      // Best regards,
      // The Auth Team`,
      html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };

    // 📬 Send the email
    await transporter.sendMail(mailOptions);

    // ✅ Respond with success
    res.json({
      success: true,
      message: "Verification OTP sent to email",
    });
  } catch (error) {
    // ❌ Handle any errors
    res.json({
      success: false,
      message: error.message,
    });
  }
};

// how OTP generation works in this line of code:

// const otp = String(Math.floor(100000 + Math.random() * 900000));

// ✅ Goal:
// Generate a 6-digit OTP (between 100000 and 999999), which is commonly used for verification.

// 🔍 Step-by-Step Explanation:
// Math.random()
// Generates a random decimal number between 0 (inclusive) and 1 (exclusive).
// Example: 0.3567, 0.9281, etc.

// Math.random() * 900000
// Multiplies that decimal by 900000, resulting in a number between 0 and 899999.999...

// Example:

// 0.3567 * 900000 = 321030.3

// 0.9281 * 900000 = 835290.9

// 100000 + ...
// Adds 100000 to shift the range from:

// 0–899999 ➝ 100000–999999

// So now, we’re guaranteed a minimum of 6 digits.

// Math.floor(...)
// Rounds the number down to the nearest integer (removes decimal part).
// Example: 835290.9 becomes 835290.

// String(...)
// Converts the numeric OTP into a string, useful when:

// Sending via email/text

// Displaying on UI

// Storing in DB

// ✅ Controller to verify user's email using the OTP
export const verifyEmail = async (req, res) => {
  // Prefer authenticated userId from middleware, fallback to body
  const userId = req.userId || req.body.userId;
  const { otp } = req.body;

  // ⚠️ Check if both userId and otp are provided
  if (!userId || !otp) {
    return res.json({
      success: false,
      message: "Missing details",
    });
  }

  try {
    // 🔍 Find the user by ID
    const user = await userModel.findById(userId);

    // ❌ User not found in database
    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    // ❌ Check if OTP is empty or incorrect
    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // ⏰ Check if the OTP has expired
    if (user.verifyOtpExpiredAt < Date.now()) {
      return res.json({
        success: false,
        message: "OTP expired",
      });
    }

    // ✅ Mark the account as verified
    user.isAccountVerified = true;

    // 🧹 Clear the OTP and its expiration time
    user.verifyOtp = "";
    user.verifyOtpExpiredAt = 0;

    // 💾 Save changes to the database
    await user.save();

    // ✅ Respond with success message
    return res.json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    // ❌ Handle any unexpected errors
    return res.json({
      success: false,
      message: error.message,
    });
  }
};

// ✅ Check if user is authenticated
export const isAuthenticated = async (req, res) => {
  try {
    // 🟢 Simply return success if the request reaches here (token/session is valid)
    res.json({
      success: true,
    });
  } catch (error) {
    // ❌ Return error message in case of failure
    res.json({
      success: false,
      message: error.message,
    });
  }
};

// 🔄 Send OTP for Password Reset
export const sendResetOtp = async (req, res) => {
  // 📨 Step 1: Extract email from request body
  const { email } = req.body;

  // ❗ Step 2: Check if email is missing
  if (!email) {
    return res.json({ success: false, message: "Email is required" });
  }

  try {
    // 🔍 Step 3: Search for user by email
    const user = await userModel.findOne({ email });

    if (!user) {
      // ❌ Step 4: If user not found, return error
      return res.json({ success: false, message: "User not found" });
    }

    // 🔢 Step 5: Generate a random 6-digit OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    // 🕒 Step 6: Store OTP and its expiration time (15 mins from now)
    user.resetOtp = otp;
    user.resetOtpExpiredAt = Date.now() + 15 * 60 * 1000;

    // 💾 Step 7: Save updated user data to database
    await user.save();

    // 📧 Step 8: Prepare password reset email content
    const mailOptions = {
      from: process.env.SENDER_EMAIL, // Sender email address
      to: user.email, // Receiver's email
      subject: "Password Reset OTP", // Subject line
      // text: `Hello,

      // We have received a request to reset your password.

      // Your one-time password (OTP) for resetting your password is: ${otp}

      // Please enter this OTP in the app to proceed with resetting your password. This OTP is valid for 24 hours.

      // If you did not request a password reset, please ignore this email.

      // Best regards,
      // The Auth Team`,// Email body
      html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace(
        "{{email}}",
        user.email
      ),
    };

    // 📤 Step 9: Send the OTP email
    await transporter.sendMail(mailOptions);

    // ✅ Step 10: Send success response to frontend
    res.json({
      success: true,
      message: "OTP sent to your email",
    });
  } catch (error) {
    // ❌ Step 11: Handle and return error
    return res.json({ success: false, message: error.message });
  }
};

// 🔐 Reset User Password using OTP
export const resetPassword = async (req, res) => {
  // 📨 Step 1: Extract email, otp, and newPassword from request body
  const { email, otp, newPassword } = req.body;

  // ❗ Step 2: Validate required fields
  if (!email || !otp || !newPassword) {
    return res.json({
      success: false,
      message: "Email, OTP, and new password are required",
    });
  }

  try {
    // 🔍 Step 3: Find the user by email
    const user = await userModel.findOne({ email });

    if (!user) {
      // ❌ Step 4: Return error if user not found
      return res.json({ success: false, message: "User not found" });
    }

    // 🔍 Step 5: Check if OTP matches
    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    // ⏳ Step 6: Check if OTP has expired
    if (user.resetOtpExpiredAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    // 🔐 Step 7: Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 💾 Step 8: Update user's password and clear OTP data
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpiredAt = 0;

    // Save changes to database
    await user.save();

    // ✅ Step 9: Send success response
    return res.json({
      success: true,
      message: "Password has been reset successfully",
    });
  } catch (error) {
    // ❌ Step 10: Handle and return error
    return res.json({ success: false, message: error.message });
  }
};
