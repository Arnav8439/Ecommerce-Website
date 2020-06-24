const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator/check');

const User = require('../models/user');

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'YOUR USERNAME',
      pass: 'PASSWORD'
    }
  
  });

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: ''
    },
    validationErrors: []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: ''
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password
      },
      validationErrors: errors.array()
    });
  }

  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid email or password.',
          oldInput: {
            email: email,
            password: password
          },
          validationErrors: []
        });
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: 'Invalid email or password.',
            oldInput: {
              email: email,
              password: password
            },
            validationErrors: []
          });
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword
      },
      validationErrors: errors.array()
    });
  }

  bcrypt
    .hash(password, 12)
    .then(hashedPassword => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] }
      });
      return user.save();
    })
    .then((result)=> {
          
      var mailOptions = {
          from: 'arnavaggarwal8755@gmail.com',
          to: email,
          subject: 'Successfully Signed up',
          html: `<h2>You have signed up Successfully</h2>`
        };
      
      transporter.sendMail(mailOptions, function(error, info){
          if (error) {
            console.log(error);
          } else {
              console.log('Email sent: ' + info.response);
            }
        });
      res.redirect('/login');

    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req,res,next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else {
      message = null;
  }
   res.render('auth/reset',{
    pageTitle : "Reset Password",
    path : '/reset',
    errorMessage : message
});
}




exports.postReset = (req,res,next) => {
   crypto.randomBytes(32,(err,buffer)=>{
        if(err) {
          console.log(err);
          return res.redirect('/reset');
        }
        const token = buffer.toString('hex');
        User.findOne({email  : req.body.email}).then(user => {
          if(!user) {
            console.log("user doesnot exist!");
            req.flash('error','Email doesnot exist!');
            return res.redirect('/reset');
          }  
          user.resetToken = token;
          user.resetTokenExpiration = Date.now() + 36000000;
          // console.log("user gets saved!" ,user.resetToken);
          return user.save();            
        })
        .then(result => {
           res.redirect('/');
           var mailOptions = {
              from: 'arnavaggarwal8755@gmail.com',
              to: req.body.email,
              subject: 'Password Reset',
              html: `
                 <p> You requested a password reset</p>
                 <p> Click this<a href="http://localhost:3000/reset/${token}"> link </a> to reset password </p>
               `
            };
          
          transporter.sendMail(mailOptions, function(error, info){
              if (error) {
                console.log(error);
              } else {
                  console.log('Email sent: ' + info.response);
                }
            });


        })
        .catch( err => console.log(err));

   });
} 

exports.getNewPassword = (req,res,next) => {
  const token  = req.params.token;
  console.log("token : ",token);
  console.log("date : ",Date.now());
  User.findOne({resetToken : token , resetTokenExpiration : {$gt : Date.now()}})
  .then(user => {
      if(!user) {
        console.log("user does not exist ort token;")
        return res.direct('/');
      }
      let message = req.flash('error'); 
      if(message.length > 0) {
          message = message[0];
      }else {
          message = null;
      }
      res.render('auth/new-password' ,{
      path : '/new-password',
      pageTitle : 'New Password',
      errorMessage : message,
      userId : user._id.toString(),
      passwordToken  : token
  });
  })
  .catch(err => {
    console.log(err);
  });  
}

exports.postNewPassword = (req,res,next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken : passwordToken,
    resetTokenExpiration : {$gt : Date.now() },
    _id : userId
  }).then(user => {
    // console.log("postNew Password, user" , user);
    resetUser = user;
    return bcrypt.hash(newPassword , 12);
  })
  .then(hashedPassword => {
    console.log("resetUser ",resetUser);
    resetUser.password = hashedPassword;
    resetUser.resetToken = undefined;
    resetUser.resetTokenExpiration = undefined;
    return resetUser.save();
  })
  .then(result => {
    console.log("password updated");
     res.redirect('/login');
  })
  .catch(err => console.log(err));

}