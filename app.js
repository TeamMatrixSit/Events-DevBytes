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

current = "";


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
    maxAge: 6000000,
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
  end_date: String,
  event_description: String,
  event_mail: String
})

const eventuserSchema = new mongoose.Schema({
  event_name: String,
  user_id: String,
  event_organizer: String,
  start_date: String,
  end_date: String
})


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
adminSchema.plugin(passportLocalMongoose);
adminSchema.plugin(findOrCreate);


//Schema Model initialize
const user = mongoose.model('user', userSchema);
const admin = mongoose.model('admin', adminSchema);
const event = mongoose.model('event', eventSchema);
const eventuser = mongoose.model("eventuser", eventuserSchema);

passport.use(user.createStrategy());

passport.serializeUser((userx, done) => {
  current = userx.id;
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
      req.flash("status", "1");
      req.flash("msg", "Successfully Signed Up!");
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
      req.flash("status", "1");
      req.flash("msg", "Successfully Access Granted!");
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

  user.findOne({
    emailId: req.body.user_email
  }, function (err, user) {
    if (err) throw err;
    if (!user) {
      req.flash("status", "2");
      req.flash("msg", "Oops No User Found");
      return done(null, false, {
        message: 'Incorrect username.'
      });
    }


    bcrypt.compare(req.body.user_password, user.password, function (err, res) {
      if (res) {
        req.flash("status", "1");
        req.flash("msg", "Successfully logged In!");
        return done(null, user);
      } else {
        req.flash("status", "2");
        req.flash("msg", "Invalid Password!");

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

  admin.findOne({
    emailId: req.body.admin_email
  }, function (err, user) {
    if (err) throw err;
    if (!user) {
      req.flash("status", "2");
      req.flash("msg", "No User Found!!");
      return done(null, false, {
        message: 'Incorrect username.'
      });
    }
    bcrypt.compare(req.body.admin_password, user.password, function (err, res) {
      if (res) {
        req.flash("status", "1");
        req.flash("msg", "Welcome Admin!");
        return done(null, user);
      } else {
        req.flash("status", "2");
        req.flash("msg", "Oops Wrong Password!");
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
    callbackURL: "https://events01.herokuapp.com/auth/google/home",
    userProfile: "https://www.googleapis.com/oauth2/userinfo"
  },
  function (accessToken, refreshToken, profile, cb) {
    const validatingmail = profile.emails[0].value;
    if (validatingmail.endsWith("@sairamtap.edu.in")) {
      user.findOrCreate({
        googleId: profile.id,
        name: profile.displayName,
        emailId: profile.emails[0].value
      }, function (err, user) {

        return cb(err, user);
      });
    } else {
      // req.flash("status", "2");
      //   req.flash("msg", "Please Use Official Mail, Else Use Signup ");
      return cb(null, false);
    }

  }
));

//Github-auth
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "https://events01.herokuapp.com/auth/github/home"
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
    const message = req.flash("msg");
    const _status = req.flash("status");
    res.render("login", {
      message,
      _status
    });

  })

app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {

    var missed = []
    var upcoming = []
    var ongoing = []

    event.find({}, (err, docs) => {
      docs.forEach(element => {
        var dd = element.start_date;
        var ed = element.end_date;
        dd = dd.toString();


        var rightNow = new Date();
        var res = rightNow.toISOString().slice(0, 10).replace(/-/g, "-");
        res = res.toString();


        if (res > ed) {
          missed.push(element);
        } else if (res <= ed && res >= dd) {
          ongoing.push(element);
        } else
          upcoming.push(element);



      });

      const message = req.flash("msg");
      const _status = req.flash("status");
      res.render("home", {
        miss: missed,
        on: ongoing,
        up: upcoming,
        message,
        _status
      });
    })



  } else
    res.redirect("/login");
})

app.get("/adminhome", (req, res) => {
  if (req.isAuthenticated()) {
    admin.findById(req.user.id, (err, docs) => {
      if (docs) {
        const message = req.flash("msg");
        const _status = req.flash("status");
        res.render("adminhome", {
          message,
          _status
        });
      } else {
        req.flash("status", "2");
        req.flash("msg", "Only Admin Can Access!");
        res.redirect("/adminlogin");
      }
    })

  } else
    res.redirect("/adminlogin");
})

app.get("/signup", (req, res) => {
  const message = req.flash("msg");
  const _status = req.flash("status");
  res.render("signup", {
    message,
    _status
  });

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
  const message = req.flash("msg");
  const _status = req.flash("status");
  res.render("adminlogin", {
    message,
    _status
  });

});

app.post('/adminlogin',
  passport.authenticate('admin-login', {
    successRedirect: '/adminhome',
    failureRedirect: '/adminlogin'
  })
);


app.get("/adminsignup", (req, res) => {
  if (req.isAuthenticated()) {
    admin.findById(req.user.id, (err, docs) => {
      if (docs) {
        const message = req.flash("msg");
        const _status = req.flash("status");
        res.render("adminsignup", {
          message,
          _status
        });
      } else {
        req.flash("status", "2");
        req.flash("msg", "Only Admin Can Access!");
        res.redirect("/adminlogin");
      }
    })


  } else {
    res.redirect("/adminlogin");
  }

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
    admin.findById(req.user.id, (err, docs) => {
      if (docs) {
        const message = req.flash("msg");
        const _status = req.flash("status");
        res.render("addevent", {
          message,
          _status
        });
      } else {
        req.flash("status", "2");
        req.flash("msg", "Only Admin Can Access!");
        res.redirect("/adminlogin");
      }
    })

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
      end_date: req.body.end_date,
      event_description: req.body.event_description,
      event_mail: req.body.event_mail

    });

    eventx.save();
    req.flash("status", "1");
    req.flash("msg", "Successfully Added Event To Our Site!");
    res.redirect("/adminhome");
  } else {
    res.redirect("/adminlogin");
  }
})

app.post("/custom", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/" + req.body.info);
  } else
    res.redirect("/login");
})
app.get("/about_us", (req, res) => {
  res.render("about_us");
})


app.get("/myregisters", (req, res) => {

  if (req.isAuthenticated()) {
    user.findById(req.user.id, (err, docs) => {
      if (docs) {
        const userid = req.user.id;
        eventuser.find({
          user_id: userid
        }, (err, docs) => {
          if (err)
            console.log(err);
          if (docs) {

            res.render("myregister", {
              info: docs
            });
          } else {
            res.render("myregister", {
              info: "Na"
            });
          }
        })
      } else {
        req.flash("status", "2");
        req.flash("msg", "Admin Can't Access, Login As User !");
        res.redirect("/home");
      }
    })


  } else {
    res.redirect("/login");
  }
});

app.post("/register", (req, res) => {
  if (req.isAuthenticated()) {
    user.findById(req.user.id, (err, docs) => {
      if (docs) {
        const userid = req.user._id;
        user.findById(userid, (err, docs) => {
          if (err)
            console.log(err);
          if (docs) {
            event.findById(req.body.info, (err, docx) => {
              if (err)
                console.log(err)
              if (docx) {
                if (eventuser.find({
                    event_name: docx.event_name,
                    user_id: docs.id
                  }, (err, found) => {
                    if (err)
                      console.log(err);
                    if (found) {
                      req.flash("status", "2");
                      req.flash("msg", "Already Registered For This Event!");

                    } else {

                      const eventuserx = new eventuser({
                        event_name: docx.event_name,
                        user_id: docs._id,
                        event_organizer: docx.event_organizer,
                        start_date: docx.start_date,
                        end_date: docx.end_date
                      })
                      eventuserx.save();
                    }
                  }))
                  eventusddrx = new eventuser({
                    event_name: docx.event_name,
                    user_id: docs._id,
                    event_organizer: docx.event_organizer,
                    start_date: docx.start_date,
                    end_date: docx.end_date
                  })
              }
            })

          }
          req.flash("status", "1");
          req.flash("msg", "Successfully Registered!");
          res.redirect("/home");
        })
      } else {
        req.flash("status", "2");
        req.flash("msg", "Sorry Admin Can't Register, Login As User!");
        res.redirect("/home");
      }
    })



  } else
    res.redirect("/login");

})

app.get("/:custom_routes", (req, res) => {
  if (req.isAuthenticated()) {
    Custom_route_Name = req.params.custom_routes;
    try {
      event.findById(Custom_route_Name, (err, docs) => {
        if (err)
          res.redirect("/");
        if (docs)
          res.render("info", {
            ele: docs
          });
      })

    } catch (err) {
      res.redirect("/");
    }

  } else
    res.redirect("/login");


})





app.listen(process.env.PORT || 3000, () => {
  console.log("server started sucessfully")
});