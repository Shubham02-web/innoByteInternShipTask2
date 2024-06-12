const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const cookie = require("cookie-parser");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

dotenv.config();
const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(cookie());
mongoose
  .connect(process.env.MongoURI)
  .then("connected succesfully")
  .catch("error in mongoconnect");

const schema = mongoose.Schema({
  userName: String,
  email: {
    type: String,
    match: /.+\@.+\..+/,
  },
  password: String,
});

const user = new mongoose.model("InternshipCollection", schema);

// creating transporter Email

const transPorter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.YourEmail,
    pass: process.env.YourPass,
  },
});

const conformationMail = (userEmail, conformationCode) => {
  const mailOptions = {
    from: process.env.YourEmail,
    to: userEmail,
    subject: "Email Conformation",
    html: `<h1>Email Conformation</h1>
    <p>Please Confirm your Email By Clicking the below link</p>,
    <a href="http:ShubhamProject.com/confirm?code=${conformationCode}">Click Me</a>`,
  };
  transPorter.sendMail(mailOptions, (err, info) => {
    if (err) console.log(`error in sending email`, err);
    else console.log(`email sent`, info.response);
  });
};
app.post("/api/signup", async function (req, res) {
  try {
    const { userName, email, password } = req.body;
    if (!userName || !email || !password)
      return res.send({
        success: false,
        message: "Please Enter all Field userName , email and Password",
      });

    const hashedPass = await bcrypt.hash(password, 10);
    const conformationCode = crypto.randomBytes(20).toString("hex");
    const temp = await user.create({
      userName,
      email,
      password: hashedPass,
      conformationCode,
    });

    temp.save();
    conformationMail(email, conformationCode);
    temp.password = undefined;
    res.status(201).send({
      success: true,
      message:
        "User Created Succesfully please check your email to conform your sign up",
      temp,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      error,
    });
  }
});

app.get("/conformation", async function (req, res) {
  try {
    const { code } = req.query;
    const User = await user.findOne({ conformationCode: code });
    if (!User) return res.status(500).send("Invalid Conformation Code");

    //   Clear Conformation code
    User.conformationCode = "";
    await User.save();
    res.status(200).send({
      success: true,
      message: "Email Conformation Successful",
      User,
    });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: "Error in Confirm Email API",
    });
  }
});
app.get("/api/login", async function (req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.send("Please enter an email and password");
    const temp = await user.findOne({ email });
    if (!temp) return res.status("User Not found for these email");
    const isMatch = await bcrypt.compare(password, temp.password);
    if (!isMatch)
      return res
        .status(500)
        .send({ success: false, message: "Invalid Cridintional" });

    const token = await jwt.sign({ email, password }, process.env.Secret);
    res.cookie("token", token).status(200).send({
      success: true,
      message: "You have logined succesfully ",
      token,
    });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: "Error in Login API",
    });
  }
});

app.get("/api/profile", async function (req, res) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(500).send("Token not found");
    const isVerified = jwt.verify(token, process.env.Secret);
    if (!isVerified)
      return res.status(500).send({
        success: false,
        message: "Invalid Token",
      });
    const { email } = isVerified;
    console.log(email);
    const temp = await user.findOne({ email });
    if (!temp)
      return res.status(500).send({
        success: false,
        message: "User not found",
      });

    temp.password = undefined;
    res.status(200).send({
      success: true,
      message: "User Profile Fatche Succesfully",
      temp,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in Profile API",
    });
  }
});
app.listen(process.env.PORT, () => {
  console.log(`listening on port no ${process.env.PORT}`);
});
