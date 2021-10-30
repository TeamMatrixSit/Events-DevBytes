require('dotenv').config(); //env 
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

//import for passport authentication
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose');
const localStrategy = require('passport-local').Strategy;
//new packages
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const bcrypt = require("bcrypt");
const flush = require("connect-flash");



const app = express();


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}))



//session initialize
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 600000,
    secure: false
  }
}));
app.use(flush());
app.use(passport.initialize());
app.use(passport.session());



//connecting to DB and initialize Schema

mongoose.connect("mongodb+srv://Admin-Spark:" + process.env.MPASS + "@cluster01.ckyib.mongodb.net/EventsDB?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});




const userSchema = new mongoose.Schema({
  googleId: String,
  githubId: String,
  name: String,
  emailId: String,
  password: String
})

const adminSchema = new mongoose.Schema({
  name: String,
  emailId: String,
  password: String
})

const eventSchema = new mongoose.Schema({
  event_name: String,
  event_organizer: String,
  event_image_url: String,
  type: String,
  start_date: String,
  event_days: Number,
  event_description: String,
  email_mail: String
})


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
adminSchema.plugin(passportLocalMongoose);
adminSchema.plugin(findOrCreate);


//Schema Model initialize
const user = mongoose.model('user', userSchema);
const admin = mongoose.model('admin', adminSchema);
const event = mongoose.model('event', eventSchema);

passport.use(user.createStrategy());

passport.serializeUser((userx, done) => {
  done(null, userx.id);
});

passport.deserializeUser(async (id, done) => {

  user.findById(id, (err, user) => {
    if (err) done(err);
    if (user) {
      done(null, user);
    } else {
      admin.findById(id, (err, user) => {
        if (err) done(err);
        done(null, user);
      })
    }
  })

});


//LOCAL AUTH FOR USERS
passport.use('signup', new localStrategy({
  usernameField: 'user_email',
  passwordField: 'user_password',
  passReqToCallback: true
}, async (req, user_email, user_password, done) => {
  user.findOne({
    emailId: req.body.user_email
  }, async (err, docs) => {
    if (err)
      return done(err)
    if (docs) {
      console.log("already");
      return done(null, false);
    } else {
      const name = req.body.user_username;
      const emailId = req.body.user_email;
      var salt = bcrypt.genSaltSync(10);
      var hash = bcrypt.hashSync(req.body.user_password, salt);
      const password = hash;
      const userx = await user.create({
        name,
        emailId,
        password
      });
      return done(null, userx);
    }
  })
}));

//LOCAL AUTH FOR ADMINS
passport.use('admin-signup', new localStrategy({
  usernameField: 'admin_email',
  passwordField: 'admin_password',
  passReqToCallback: true
}, async (req, admin_email, admin_password, done) => {
  admin.findOne({
    emailId: req.body.admin_email
  }, async (err, docs) => {
    if (err)
      return done(err)
    if (docs) {
      console.log("already");
      return done(null, false);
    } else {
      const name = req.body.admin_username;
      const emailId = req.body.admin_email;
      var salt = bcrypt.genSaltSync(10);
      var hash = bcrypt.hashSync(req.body.admin_password, salt);
      const password = hash;
      const userx = await admin.create({
        name,
        emailId,
        password
      });
      return done(null, userx);
    }
  })
}));



//LOCAL AUTH FOR USER- LOGIN
passport.use('login', new localStrategy({
  usernameField: 'user_email',
  passwordField: 'user_password',
  passReqToCallback: true

}, async (req, user_email, user_password, done) => {
  console.log(req.body);
  user.findOne({
    emailId: req.body.user_email
  }, function (err, user) {
    if (err) throw err;
    if (!user) {
      console.log('Unknown User');
      return done(null, false, {
        message: 'Incorrect username.'
      });
    }


    bcrypt.compare(req.body.user_password, user.password, function (err, res) {
      if (res) {
        return done(null, user);
      } else {
        console.log('Invalid Password');
        return done(null, false, {
          message: 'Incorrect password.'
        });
      }

    });


  });

}));


//LOCAL AUTH FOR ADMIN- LOGIN
passport.use('admin-login', new localStrategy({
  usernameField: 'admin_email',
  passwordField: 'admin_password',
  passReqToCallback: true

}, async (req, admin_email, admin_password, done) => {
  console.log(req.body);
  admin.findOne({
    emailId: req.body.admin_email
  }, function (err, user) {
    if (err) throw err;
    if (!user) {
      console.log('Unknown User');
      return done(null, false, {
        message: 'Incorrect username.'
      });
    }
    bcrypt.compare(req.body.admin_password, user.password, function (err, res) {
      if (res) {
        return done(null, user);
      } else {
        console.log('Invalid Password');
        return done(null, false, {
          message: 'Incorrect password.'
        });
      }

    });


  });

}));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECERT,
    callbackURL: "http://localhost:3000/auth/google/home",
    userProfile: "https://www.googleapis.com/oauth2/userinfo"
  },
  function (accessToken, refreshToken, profile, cb) {

    user.findOrCreate({
      googleId: profile.id,
      name: profile.displayName,
      emailId: profile.emails[0].value
    }, function (err, user) {
      return cb(err, user);
    });

  }
));

//Github-auth
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/home"
  },
  function (accessToken, refreshToken, profile, done) {

    user.findOrCreate({

      githubId: profile.id,
      name: profile.displayName

    }, function (err, user) {
      return done(err, user);
    });
  }
));


//Routing...

//Google
app.get('/auth/google',
  passport.authenticate('google', {

    scope: [
      'profile',
      'https://www.googleapis.com/auth/plus.me', // request access here
      'https://www.googleapis.com/auth/userinfo.email'
    ]
  })
);


app.get('/auth/google/home',
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function (req, res) {

    res.redirect("/home"); //successful login
  });


//Github
app.get('/auth/github',
  passport.authenticate('github', {
    scope: ['profile', "email"]
  }));

app.get('/auth/github/home',
  passport.authenticate('github', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/home");
  });



app.route("/login")
  .get((req, res) => {
    res.render("login");
  })

app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    var missed=[]
    var upcoming=[]
    var ongoing=[]
    event.find({}, (err, docs) => {
      docs.forEach(element => {
        var dd = element.start_date;
        dd=dd.toString();
        

        var rightNow = new Date();
        var res = rightNow.toISOString().slice(0,10).replace(/-/g,"-");
        res=res.toString();


        if(res>dd)
        {
          missed.push(element);
        }
        else if(res==dd)
        {
          ongoing.push(element);
        }
        else
        upcoming.push(element);

      

      });


      res.render("home",{miss:missed , on : ongoing , up: upcoming});
    })



  } else
    res.redirect("/login");
})

app.get("/adminhome", (req, res) => {
  if (req.isAuthenticated())
    res.render("adminhome");
  else
    res.redirect("/adminlogin");
})

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post('/signup', passport.authenticate('signup', {
  successRedirect: '/home',
  failureRedirect: '/signup'
}));

app.post('/login',
  passport.authenticate('login', {
    successRedirect: '/home',
    failureRedirect: '/login'
  })
);

app.get("/adminlogin", (req, res) => {
  res.render("adminlogin");
});

app.post('/adminlogin',
  passport.authenticate('admin-login', {
    successRedirect: '/adminhome',
    failureRedirect: '/adminlogin'
  })
);


app.get("/adminsignup", (req, res) => {
  res.render("adminsignup");
});

app.post('/adminsignup', passport.authenticate('admin-signup', {
  successRedirect: '/adminhome',
  failureRedirect: '/adminsignup'
}));
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/addevent", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("addevent");
  } else {
    res.redirect("/adminlogin");
  }
})




app.post("/addevent", (req, res) => {
  if (req.isAuthenticated()) {
    const eventx = new event({

      event_name: req.body.event_name,
      event_organizer: req.body.event_organizer,
      event_image_url: req.body.event_image_url,
      type: req.body.type,
      start_date: req.body.start_date,
      event_days: req.body.event_days,
      event_description: req.body.event_description,
      event_mail: req.body.event_mail

    });

    eventx.save();
    res.redirect("/adminhome");
  } else {
    res.redirect("/adminlogin");
  }
})

app.listen(process.env.PORT || 3000, () => {
  console.log("server started sucessfully")
});