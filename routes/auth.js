const express = require('express');
const User = require('../models/User');
const {body,validationResult} = require('express-validator');
const bcrypt = require('bcryptjs');
const JWT_Secret = '$Cristi07';
var fetchuser = require('../middleware/fetchuser')
var jwt = require('jsonwebtoken');


const router = express.Router();
//Route 1:Create a User using POST "/api/auth/createUser". No login required
router.post('/createUser',[
    body('name','Enter a valid name').isLength({min:3}),
    body('email','Enter a valid email').isEmail(),
    body('password','Password must be atleat 5 characters').isLength({min:5})
],async(req,res)=>{
    let success=false
    // If there are errors return Bad Request and errors.
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({success,errors:errors.array()});
    }
    //  Check whether the user with this eamil already exists
    try{
    let user = await User.findOne({email:req.body.email});
    if(user){
        return res.status(400).json({success,error:"Sorry a user with this email already exists!"})
    }
    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password,salt)
    user = await User.create({
        name:req.body.name,
        password:secPass,
        email:req.body.email
    })
    const data = {
        user:{
            id:user.id
        }
    }
    const authtoken = jwt.sign(data,JWT_Secret)
    success=true
    res.json({success,authtoken})
    // res.json(user)
  }catch(error){
    console.error(error.message);
    res.status(500).json("Internal server error")
  }
})

//Route 2:Authenticate a User using POST "/api/auth/login". No login required
router.post('/login',[
    body('email','Enter a valid email').isEmail(),
    body('password','Password cannot be blank').exists()
],async(req,res)=>{
    let success=false
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors:errors.array()});
    }

    const{email,password} = req.body;
    try {
        let user = await User.findOne({email});
        if(!user){
            return res.status(400).json({error:"Please try to login with correct credentials"})
        }

        const passwordCompare = await bcrypt.compare(password,user.password);
        if(!passwordCompare){
            success=false
            return res.status(400).json({success,error:"Please try to login with correct credentials"})
        }

        const data = {
            user:{
                id:user.id
            }
        }
        const authtoken = jwt.sign(data,JWT_Secret)
        success=true;
        res.json({success,authtoken})
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal server error")
    }
})

//Route 3:Get loggedIn User details using POST "/api/auth/getUser". Login is required
router.post('/getUser',fetchuser,async(req,res)=>{

try {
    const userId = req.user.id
    const user = await User.findById(userId).select("-password")
    res.send(user)
} catch (error) {
    console.error(error.message);
    res.status(500).json("Internal server error")
}
})
module.exports = router