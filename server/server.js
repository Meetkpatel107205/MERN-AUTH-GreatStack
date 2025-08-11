
import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 4000;
connectDB();

const allowedOrigins = ['http://localhost:5173']

// Parse incoming JSON requests and put the parsed data in req.body
app.use(express.json());
// Parse cookies attached to the client request object (req.cookies)
app.use(cookieParser());
// Enable CORS and allow credentials (cookies, authorization headers, etc.) to be sent in cross-origin requests
app.use(
  cors({ 
    origin: allowedOrigins,
    // Allow requests from this origin
    credentials: true, // Allow cookies and auth headers in requests
  })
);

// API Endpoints
app.get("/", (req, res) => {
    res.send("API Working");
});
// Use the authRouter for all auth-related routes
// All routes defined in authRouter will now be prefixed with /api/auth
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

app.listen(port, () => {
    console.log(`Server started on PORT : ${port}`);
});
