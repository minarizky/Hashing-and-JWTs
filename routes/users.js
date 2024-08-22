const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { ensureLoggedIn, ensureCorrectUser } = require('../middleware/auth');
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

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 **/
router.get('/', ensureLoggedIn, async function (req, res, next) {
  try {
    const users = await User.all();
    return res.json({ users });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 **/
router.get('/:username', ensureLoggedIn, ensureCorrectUser, async function (req, res, next) {
  try {
    const user = await User.get(req.params.username);
    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 **/
router.get('/:username/to', ensureLoggedIn, ensureCorrectUser, async function (req, res, next) {
  try {
    const messages = await User.messagesTo(req.params.username);
    return res.json({ messages });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 **/
router.get('/:username/from', ensureLoggedIn, ensureCorrectUser, async function (req, res, next) {
  try {
    const messages = await User.messagesFrom(req.params.username);
    return res.json({ messages });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
