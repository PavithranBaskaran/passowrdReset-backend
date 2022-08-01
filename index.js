const express = require("express");
const app = express();
const mongodb = require("mongodb");
const mongoClient = mongodb.MongoClient;
const dotenv = require("dotenv").config;
const cors = require("cors");
var nodemailer = require("nodemailer");
var randomstring = require("randomstring");

const URL =
  process.env.DB ||
  "mongodb+srv://user:user@cluster0.apdks2v.mongodb.net/?retryWrites=true&w=majority";

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
//MiddleWare
app.use(express.json());
app.use(
  cors({
    origin: "*",
  })
);

let authenticate = function (request, response, next) {
  // console.log(request.headers);
  if (request.headers.authorization) {
    let verify = jwt.verify(
      request.headers.authorization,
      process.env.SECRET || "IFNSLT8px6NzjFPI9jhl"
    );
    console.log(verify);
    if (verify) {
      request.userid = verify.id;

      next();
    } else {
      response.status(401).json({
        message: "Unauthorized",
      });
    }
  } else {
    response.status(401).json({
      message: "Unauthorized",
    });
  }
};

app.post("/register", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(request.body.password, salt);
    request.body.password = hash;
    await db.collection("users").insertOne(request.body);
    await connection.close();
    response.json({
      message: "User Registered!",
    });
  } catch (error) {
    console.log(error);
  }
});

app.post("/", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const user = await db
      .collection("users")
      .findOne({ username: request.body.username });

    if (user) {
      const match = await bcrypt.compare(request.body.password, user.password);
      if (match) {
        //Token
        const token = jwt.sign(
          { id: user._id, username: user.username },
          process.env.SECRET || "IFNSLT8px6NzjFPI9jhl"
        );
        // console.log(token);
        response.json({
          message: "Successfully Logged In!!",
          token,
        });
      } else {
        response.json({
          message: "Password is incorrect!!",
        });
      }
    } else {
      response.json({
        message: "User not found",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/dashboard", authenticate, async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    request.body.userid = mongodb.ObjectId(request.userid);
    // request.body.userid = mongodb.ObjectId(request.userid)
    await db.collection("data").insertOne(request.body);
    await connection.close();
    response.json({
      message: "Data added!!",
    });
  } catch (error) {
    console.log(error);
  }
});

app.get("/dashboard", authenticate, async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    let userdata = await db
      .collection("data")
      .find({ userid: mongodb.ObjectId(request.userid) })
      .toArray();
    await connection.close();
    response.json(userdata);
  } catch (error) {
    console.log(error);
  }
});

app.post("/resetpassword", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const user = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (user) {
      let mailid = request.body.email;
      let rString = randomstring.generate(7);
      let link = "http://localhost:3000/reset-password-page";
      await db
        .collection("users")
        .updateOne({ email: mailid }, { $set: { rString: rString } });
      await connection.close();

      var transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "testnodemail04@gmail.com",
          pass: "vkoi jqcf ejsx wvni" || process.env.pass,
        },
      });

      var mailOptions = {
        from: "testnodemail04@gmail.com",
        to: mailid,
        subject: "Password Reset",
        text: `Your Random text is ${rString}. Click the link to reset password ${link}`,
        html: `<h2> Your Random text is ${rString}. Click the link to reset password ${link}</h2>`,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
          response.json({
            message: "Email not send",
          });
        } else {
          console.log("Email sent: " + info.response);
          response.json({
            message: "Email Send",
          });
        }
      });
      response.json({
        message: "Email Send",
      });
    } else {
      response.json({
        message: "Email Id not match / User not found",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/reset-password-page", async function (request, response) {
  let mailid = request.body.email;
  let String = request.body.rString;
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(request.body.password, salt);
    request.body.password = hash;
    const user = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (user) {
      if (user.rString === request.body.rString) {
        await db
          .collection("users")
          .updateOne(
            { rString: String },
            { $set: { password: request.body.password } }
          );
        response.json({
          message: "Password reset done",
        });
      } else {
        response.json({
          message: "Random String is incorrect",
        });
      }
    } else {
      response.json({
        message: "Email Id not match / User not found",
      });
    }
    await db
    .collection("users")
    .updateOne(
      { rString: String },
      { $unset: { rString:'' } }
    );

  } catch (error) {
    console.log(error);
  }
});
//Port
app.listen(process.env.PORT || 3001);
