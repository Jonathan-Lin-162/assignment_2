require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const port = process.env.PORT || 3000;
const saltRound = 12;

const app = express();
const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_user_collection = process.env.MONGODB_USER_COLLECTION;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_collection = process.env.MONGODB_SESSION_COLLECTION;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = include("databaseConnection");
const userCollection = database
  .db(mongodb_user_database)
  .collection(mongodb_user_collection);

app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set("view engine", "ejs");

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  collectionName: mongodb_session_collection,
  crypto: {
    secret: mongodb_session_secret,
  },
});

const navLinks = [
  { name: "Home", url: "/" },
  { name: "Login", url: "/login" },
  { name: "Members", url: "/members" },
  { name: "Admin", url: "/admin" },
  { name: "Logout", url: "/logout" },
];

const signupSchema = Joi.object({
  username: Joi.string().alphanum().max(20).required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const emailSchema = Joi.string().email().required();

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
      maxAge: expireTime,
    },
  }),
);

function getPath(req) {
  const pathFolders = req.path.split("/").slice(1);
  const folder = "/" + pathFolders[0];
  return folder;
}

function isValidSession(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
}

function isAdmin(req) {
  return req.session.user_type === "admin";
}

function adminAuthorization(req, res, next) {
  const folder = getPath(req);
  if (!isAdmin(req)) {
    res.status(403);
    return res.render("message", {
      navLinks: navLinks,
      folder: folder,
      message: "403 - You are not authorized.",
      redirect: "",
    });
  } else {
    next();
  }
}

function displayMessage(res, navLinks, folder, redirect, message) {
  return res.render("message", {
    folder: folder,
    message: message,
    redirect: redirect,
    navLinks: navLinks,
  });
}

app.get("/", (req, res) => {
  const folder = getPath(req);
  if (!req.session.authenticated) {
    res.render("index", {
      navLinks: navLinks,
      folder: folder,
    });
  } else {
    res.render("main", {
      username: req.session.username,
      navLinks: navLinks,
      folder: folder,
    });
  }
});

app.get("/signUp", (req, res) => {
  const folder = getPath(req);
  res.render("signup", {
    navLinks: navLinks,
    folder: folder,
  });
});

app.post("/signupSubmit", async (req, res) => {
  let username = req.body.username;
  let email = req.body.email;
  let password = req.body.password;

  const folder = getPath(req);

  if (!username) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "signUp",
      "User name is required.",
    );
  }
  if (!email) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "signUp",
      "Email is required.",
    );
  }
  if (!password) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "signUp",
      "Password is required.",
    );
  }

  const result = signupSchema.validate({ username, email, password });
  if (result.error) {
    return displayMessage(res, navLinks, folder, "signUp", "Invalid input.");
  }

  const existingUser = await userCollection.findOne({ email });

  if (existingUser) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "signUp",
      "Email already exists.",
    );
  }

  const hashedPassword = await bcrypt.hash(password, saltRound);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.username = username;
  req.session.email = email;
  req.session.authenticated = true;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;

  return res.redirect("/members");
});

app.get("/login", (req, res) => {
  const folder = getPath(req);
  res.render("login", {
    navLinks: navLinks,
    folder: folder,
  });
});

app.post("/loginSubmit", async (req, res) => {
  const folder = getPath(req);
  const email = req.body.email;
  const password = req.body.password;

  if (!email) {
    return displayMessage(res, navLinks, folder, "login", "Email is required.");
  }
  if (!password) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "login",
      "Password is required.",
    );
  }

  const validationResult = loginSchema.validate({ email, password });
  if (validationResult.error != null) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "login",
      "Invalid email/password.",
    );
  }

  const result = await userCollection.findOne({ email });

  if (!result) {
    return displayMessage(
      res,
      navLinks,
      folder,
      "login",
      "Email does not exist.",
    );
  }
  if (await bcrypt.compare(password, result.password)) {
    req.session.authenticated = true;
    req.session.username = result.username;
    req.session.email = result.email;
    req.session.user_type = result.user_type;
    req.session.cookie.maxAge = expireTime;

    return res.redirect("/members");
  } else {
    return displayMessage(res, navLinks, folder, "login", "Password is wrong.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  return res.redirect("/");
});

app.get("/members", isValidSession, (req, res) => {
  const folder = getPath(req);
  const images = ["image1.jpg", "image2.jpg", "image3.jpg"];

  res.render("members", {
    username: req.session.username,
    images: images,
    navLinks: navLinks,
    folder: folder,
  });
});

app.get("/admin", isValidSession, adminAuthorization, async (req, res) => {
  const folder = getPath(req);
  const users = await userCollection.find().toArray();
  res.render("admin", {
    navLinks: navLinks,
    folder: folder,
    users: users,
    email: req.session.email,
  });
});

app.post(
  "/admin/promote",
  isValidSession,
  adminAuthorization,
  async (req, res) => {
    const { email } = req.body;
    const validatedResult = emailSchema.validate(email);
    if (validatedResult.error) {
      return res.redirect("/admin");
    }
    await userCollection.updateOne({ email }, { $set: { user_type: "admin" } });
    res.redirect("/admin");
  },
);

app.post(
  "/admin/demote",
  isValidSession,
  adminAuthorization,
  async (req, res) => {
    const { email } = req.body;
    const validatedResult = emailSchema.validate(email);
    if (validatedResult.error) {
      return res.redirect("/admin");
    }

    await userCollection.updateOne({ email }, { $set: { user_type: "user" } });
    res.redirect("/admin");
  },
);

app.use((req, res) => {
  const folder = getPath(req);
  res.status(404);
  res.render("404", {
    navLinks: navLinks,
    folder: folder,
  });
});

app.listen(port, (req, res) => {
  console.log("App is listening on port " + port);
});
