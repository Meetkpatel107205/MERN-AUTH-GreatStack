
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {             // ---> Name of User
        type: String,
        required: true
    },
    email: {            // ---> Email Address of User
        type: String,
        required: true,
        unique: true,
    },
    password: {         // ---> Password of Account to be created
        type: String,
        required: true
    },
    verifyOtp: {        // ---> OTP(One Time Password) for Email Verification
        type: String,
        default: ''
    },
    verifyOtpExpiredAt: {        // ---> OTP expiration period for verify OTP
        type: Number,
        default: 0
    },
    isAccountVerified: {         // ---> Account Verification Check
        type: Boolean,
        default: false
    },
    resetOtp: {        // ---> OTP for reset password
        type: String,
        default: ''
    },
    resetOtpExpiredAt: {        // ---> OTP expiration period for reset OTP
        type: Number,
        default: 0
    },
});

const userModel = mongoose.models.user || mongoose.model('user', userSchema);
// ---> First check that the userModel is available in the database or not if yes then use that userModel
//      Otherwise create new userModel.

export default userModel;