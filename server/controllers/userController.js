
import userModel from "../models/userModel.js";

// 📄 Get User Data Controller
export const getUserData = async (req, res) => {
    try 
    {
        // 📨 Step 1: Extract userId from request body
        const { userId } = req.body;

        // 🔍 Step 2: Search for user in database by ID
        const user = await userModel.findById(userId);

        if (!user)
        {
            // ❌ Step 3: If user not found, return error response
            return res.json({ success: false, message: "User not found" });
        }

        // ✅ Step 4: Return success response with selected user data
        res.json({
            success: true,
            userData: {
                name: user.name,                  // User's full name
                isAccountVerified: user.isAccountVerified // Account verification status (true/false)
            }
        });
    } 
    catch (error)
    {
        // ❌ Step 5: Handle and return server error
        res.json({ success: false, message: error.message });
    }
};
