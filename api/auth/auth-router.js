const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs');

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password, role_name } = req.body;

    // Trim and validate role_name
    const trimmedRoleName = (role_name || '').trim();
    if (trimmedRoleName.length > 32) {
      return res.status(400).json({ message: "Role name must be 32 characters or less" });
    }
    if (trimmedRoleName.toLowerCase() === 'admin') {
      return res.status(403).json({ message: "Cannot register with role 'admin'" });
    }

    // Hash the password
    const hash = bcrypt.hashSync(password, 8);

    // Add the user to the database
    const newUser = await Users.add({
      username,
      password: hash, // Save the hashed password
      role_name: trimmedRoleName
    });

    // Respond with the newly created user
    res.status(201).json(newUser);
  } catch (err) {
    next(err); // Pass any errors to the error handling middleware
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
let { username, password } = req.body;

Users.findBy({ username })
     .first()
     .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user)
        res.status(200).json({
          message: `Welcome ${user.username}!, have a token...`,
          token, 
        })
      }else {
        res.status(401).json({message: 'Invalid Credentials'})
      }
     })
     .catch(err => {
      res.status(500).json(err)
     })
});


function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username
  }
  const options = {
    expiresIn: '1d',
  }

  return jwt.sign(payload, JWT_SECRET, options)
}


module.exports = router;
