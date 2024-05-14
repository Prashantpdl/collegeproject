const express = require('express')
const router = express.Router();
const jwt = require('jsonwebtoken')
const User = require('../models/userModel');

const userController = require('../controller/userController')
const authController = require('../controller/authController')

//signup and login routes
router.delete('/:id', userController.deleteTour)
router.post('/addedby', async (req, res) => {
        
    try {
      const users = await User.find({ addedBy: req.body.id });
      res.json({ status: 'success',users});
      console.log(users)
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server Error' });
    }
});
router.post('/savetoken',userController.saveotp)
router.post('/checkopt', userController.checkOtp)
router.post('/changepassword', userController.changePassword)
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/getuserfromtoken', async (req,res) =>{
    try{
        const decoded = jwt.decode(req.body.token)
       const dataToSend =  await User.findById(decoded.id)
       res.send(dataToSend)
    }catch(err){
        console.log(err)
    }
});

//forgot password and reset password routes


//protect all routes after this middleware
// router.use(authController.protect);


//restricted all routes after this middleware for admin only
// router.use(authController.restrictTo('admin'))
router.patch('/update/:id', userController.updateUser)
router
    .route('/')
    .get(userController.getAllUsers)
    .post(userController.createUser)

router
    .route('/:id')
    .get(userController.getUser)
    .patch(userController.updateUser)
    .delete(userController.deleteUser)
router
    .route('/addedby')
    .get(userController.getAddedBy)
    // console.log(req.body)
        // try {
        //   const users = await User.find({ addedBy: req.body.id });
        //   res.json(users);
        // } catch (err) {
        //   console.error(err);
        //   res.status(500).json({ message: 'Server Error' });
        // }



module.exports = router;