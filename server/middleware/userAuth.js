
// 🔐 Middleware to authenticate user using JWT from cookies
import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    // 🍪 Extract the token from cookies
    const { token } = req.cookies;

    // ❌ If no token is present, deny access
    if (!token) {
        return res.json({
            success: false,
            message: "Not authorized. Please log in again."
        });
    }

    try {
        // 🔍 Verify and decode the token using JWT secret
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        // ✅ If token contains user ID, attach it to request body
        if (decodedToken.id) {
             req.userId = decodedToken.id;   // ✅ best practice
            // 🟢 Continue to next middleware or controller
            next();
        } else {
            return res.json({
                success: false,
                message: "Not authorized. Invalid token."
            });
        }

    } catch (error) {
        // ❌ Handle token verification errors (e.g., expired or invalid token)
        return res.json({
            success: false,
            message: error.message
        });
    }
};

export default userAuth;
