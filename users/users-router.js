const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("./users-model");
const restrict = require("../middleware/restrict");

const router = express.Router();

// GET | /api/users | If the user is logged in, respond with an array
// of all the users contained in the database. If the user is not logged in
// respond with the correct status code and the message: 'You shall not pass!'.                                                                  |
router.get("/api/users", restrict("normal"), async (req, res, next) => {
  try {
    res.json(await Users.find());
  } catch (err) {
    return res.status(401).err.json({
      message: "You shall not pass!",
    });
  }
});

// POST | /api/register | Creates a `user` using the information
// sent inside the `body` of the request. **Hash the password**
// before saving the user to the database.
router.post("/api/register", async (req, res, next) => {
  try {
    const { username, password, department } = req.body;
    const user = await Users.findBy({ username }).first();

    if (user) {
      return res.status(409).json({
        message: "Username is already taken",
      });
    }

    const newUser = await Users.add({
      username,
      password: await bcrypt.hash(password, 14),
      department,
    });

    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

// POST | /api/login | Use the credentials sent inside the `body`
// to authenticate the user. On successful login, create a new JWT with
// the user id as the subject and send it back to the client.
// If login fails, respond with the correct status code and the message: 'You shall not pass!'
router.post("/api/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await Users.findBy({ username }).first();

    if (!user) {
      return res.status(401).json({
        message: "You shall not pass!",
      });
    }

    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      return res.status(401).json({
        message: "You shall not pass!",
      });
    }

    const tokenPayload = {
      userId: user.id,
      username: user.username,
      userRole: "normal",
    };

    res.cookie("token", jwt.sign(tokenPayload, process.env.JWT_SECRET));
    res.json({
      message: `Welcome ${user.username}!`,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
