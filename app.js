require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const port = process.env.port || 3000;
const saltRound = 12;

const app = express();
const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = include("databaseConnection");
const userCollection = database
  .db(mongodb_user_database)
  .collection("user_collection");

app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${encodeURIComponent(mongodb_password)}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

app.get("/", (req, res) => {
  res.send(`
        <h1>Home</h1>
        <a href="/signUp">
        <button>Sign Up</button>
        </a>
        <a href="/login">
        <button>Login</button>
        </a>
        `);
});

app.get("/signUp", (req, res) => {
  let html = `
        Sign Up
        <form action="/signupSubmit" method="post">
        <input type="text" name="username" placeholder="username">
        <input type="email" name="email" placeholder="email">
        <input type="password" name="password" placeholder="password">
        <input type="submit" value="submit">
        </form>
        `;
  res.send(html);
});

app.post("/signupSubmit", async (req, res) => {
  let username = req.body.username;
  let email = req.body.email;
  let password = req.body.password;

  if (!username) {
    return res.send(`User Name is required. <a href="/signUp">Try again</a>`);
  }
  if (!email) {
    return res.send(`Email is required. <a href="/signUp">Try again</a>`);
  }
  if (!password) {
    return res.send(`Password is required. <a href="/signUp">Try again</a>`);
  }
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const result = schema.validate({ username, email, password });
  if (result.error != null) {
    return res.send(`Invalid input. <a href="/signUp">Try again</a>`);
  }

  const hashedPassword = await bcrypt.hash(password, saltRound);

  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
  });

  req.session.username = username;
  req.session.email = email;
  req.session.authenticated = true;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  let html = `
        Login
        <form action="/loginSubmit" method="post">
        <input type="email" name="email" placeholder="email">
        <input type="password" name="password" placeholder="password">
        <input type="submit" value="submit">
        </form>
        `;
  res.send(html);
});

app.post("/loginSubmit", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    return res.send(
      `Invalid email/password combination <a href="/login">Try again</a>`,
    );
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ username: 1, email: 1, password: 1, _id: 1 })
    .toArray();
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compareSync(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    console.log("incorrect password");
    res.redirect("/login");
    return;
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
  }

  const images = ["image1.jpg", "image2.jpg", "image3.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
      <h2>Hello, ${req.session.username}.</h2>
      <img src=image/${randomImage} alt="image" width="300px">
      <a href="/logout">
      <button>Logout</button>
      </a>  
    `);
});

app.use((req, res) => {
  res.status(404);
  res.send("page not found - 404");
});

app.listen(port, (req, res) => {
  console.log("App is listening on port " + port);
});
