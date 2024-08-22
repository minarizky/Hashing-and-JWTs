const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { SECRET_KEY } = require('../config');
const ExpressError = require('../expressError');

const router = new express.Router();

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 **/
router.post('/login', async function (req, res, next) {
  try {
    const { username, password } = req.body;
    const user = await User.authenticate(username, password);

    if (user) {
      const token = jwt.sign({ username }, SECRET_KEY);
      await User.updateLoginTimestamp(username);
      return res.json({ token });
    }

    throw new ExpressError("Invalid username/password", 400);
  } catch (err) {
    return next(err);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 * Make sure to update their last-login!
 */
router.post('/register', async function (req, res, next) {
  try {
    const newUser = await User.register(req.body);
    const token = jwt.sign({ username: newUser.username }, SECRET_KEY);
    await User.updateLoginTimestamp(newUser.username);
    return res.json({ token });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;

