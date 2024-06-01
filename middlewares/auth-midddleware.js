import jwt from 'jsonwebtoken';
import UserModel from '../models/User.js';
import dotenv from 'dotenv'
dotenv.config()

var checkUserAuth = async (req,res,next)=>{
    let token
    const {authorization} = req.headers
    if(authorization && authorization.startsWith('Bearer')){
        try{
            // Get token from header
            token = authorization.split(' ')[1];
            // Verify token
            const { userId }=jwt.verify(token , process.env.JWT_SECRET_KEY);
            // get user from token
            console.log(userId)
            req.user = await UserModel.findById(userId).select('-password')
            next();
        }
        catch(error){
            console.log(error);
            res.status(401).send({"status":"failed","messege":"Unauthorised User"});
        }
    }

    if(!token){
        res.status(401).send({'status':'failed', "messege":"Unauthorised user , No token"});
    }
}

export default checkUserAuth;