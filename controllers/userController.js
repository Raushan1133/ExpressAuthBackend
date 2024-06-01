import UserModel from "../models/User.js";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from "../configs/emailConfig.js";
import dotenv from 'dotenv'
dotenv.config()
 
class UserController {
    static userRegistration = async (req,res) =>{
        const {name , email , password,  password_confirmation , tc} = req.body;

        const user = await UserModel.findOne({email:email});

        if(user){
            res.send({"status":"failed", "messege":'Email already exists' })
        }else{
            if(name && email && password && password_confirmation && tc){
                if(password === password_confirmation){
                    try{
                        const salt = await bcrypt.genSalt(10);

                        const hashPassword = await bcrypt.hash(password,salt);
                    const doc = new UserModel({
                        name:name,
                        email:email,
                        password:hashPassword,
                        tc:tc
                    })
                    await doc.save();
                    const saved_user = await UserModel.findOne({email:email});
                    // generate jwt token
                    const token = jwt.sign({userId:saved_user._id}, process.env.JWT_SECRET_KEY, {expiresIn:'5d'});
                    res.send({"status":"success","messege":"Registered successfully", "token":token});
                    }
                    catch(error){
                        res.send({"status":"failed", "messege":'unable to register' })
                    }
                }else{
                    res.send({"status":"failed", "messege":'Password and confirm password doesnt match' });
                }
            }else{
                res.send({"status":"failed", "messege":'All fields are required' })
            }
        } 
    }

    static userLogin = async (req,res) =>{
        try{
            const  { email , password} = req.body;
            if(email && password){
                const user =await UserModel.findOne({email:email});
                if(user != null){
                    const isMatch = await bcrypt.compare(password, user.password);
                    if((user.email === email) && isMatch){
                        const token = jwt.sign({userId:user._id}, process.env.JWT_SECRET_KEY, {expiresIn:'5d'});
                        res.send({"status":"success","token":token});
                    }else{
                        res.send({"status":"failed", "messege":"email or password is not valid."});
                    }
                }else{ 
                    res.send({"status": "User not registered yet"});
                }
            }else{
                res.send({"status":"failed", "messege":"all fields are required"})
            }
        }
        catch(error){
            res.send({messege:"Login failed"});
        }
    }

    static changeUserPassword = async (req,res)=> {
        const {password , password_confirmation} = req.body;
        if(password && password_confirmation){
            if(password !== password_confirmation){
                res.send({'status':'failed','messege':'new password and confirm passeord doesnt match'})
            }else{
                const salt =await bcrypt.genSalt(10);
                const newHashPassword =await bcrypt.hash(password,salt);
                await UserModel.findByIdAndUpdate(req.user._id,{$set:{password:newHashPassword}})
                res.send({"status":"success","messege":"password changed successfully"});
            }
        }else{
            res.send({"status":"failed","messege":"All fields are required"});
        }
    }

    static loggedUser = async (req,res)=>{
        res.send({"user": req.user });
    }

    static sendUserPasswordResetEmail = async (req,res)=>{
        const {email} =req.body;
        if(email){
            const user = await UserModel.findOne({email:email});
            if(user){
            
                const secret = user._id + process.env.JWT_SECRET_KEY
                const token = jwt.sign({userID:user._id} , secret ,{expiresIn:'15m'});
                const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`;
                // Send email
                let info  = await transporter.sendMail({
                    from:process.env.EMAIL_FROM,
                    to:user.email,
                    subject:'Raushan Project - password reset link',
                    html:`<a href=${link}>Click here </a> to Reset your password`
                })
                res.send({"status":"success","messege":"Password reset Sent... Please check Your Email", "info":info})
            }else{
                res.send({"status":"failed","messege":"user doesn't exist"});
            }
        }else{
            res.send({"status":"failed","messege":"Email is required"});
        }
    }

    static userPasswordReset = async (req,res)=>{
        const {password,password_confirmation} = req.body;
        const {id,token} = req.params;
        const user= await UserModel.findById(id);
        const new_secret = user._id + process.env.JWT_SECRET_KEY;
        try{
            jwt.verify(token,new_secret);
            if(password && password_confirmation){
                if(password !== password_confirmation){
                    res.send({"status":"failed","messege":"Password and confirm password doesn't matched"});
                }else{
                    const salt = bcrypt.genSalt(10);
                   const newHashPassword = bcrypt.hash(password,salt);
                   await UserModel.findByIdAndUpdate(user._id, {$set:{
                    password:newHashPassword
                   }})
                   res.send({"status":"failed","messege":"Password reset successfully"});
                }
            }else{
                res.send({"status":"failed","messege":"All fields are required"});
            }
        }
        catch(error){
            res.send({"status":"failed","messege":"Reset password failed"})
        }
    }

}

export default UserController;