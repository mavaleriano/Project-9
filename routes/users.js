'use strict';

const express = require('express');
// Constructing router instance
const router = express.Router();
const bcryptjs = require('bcryptjs');
const auth = require('basic-auth');
const User = require("../models").User;
const { check, validationResult } = require('express-validator/check');


/* Handler function to wrap each route. */
function asyncHandler(cb){
  return async(req, res, next) => {
    try {
      await cb(req, res, next)
    } catch(error)
    {
      next(error);
    }
  }
}

const authenticateUser = async (req, res, next) => {
  let message = null;

  // Parse the user's credentials from the Authorization header.
  const credentials = auth(req);

  // If the user's credentials are available...
  if (credentials) {
    // Attempt to retrieve the user from the data store
    // by their username (i.e. the user's "key"
    // from the Authorization header).
    //const user = users.find(u => u.username === credentials.name);
    const user = await User.findOne( {where: {emailAddress: credentials.name} });

    // If a user was successfully retrieved from the data store...
    if (user) {
      // Use the bcryptjs npm package to compare the user's password
      // (from the Authorization header) to the user's password
      // that was retrieved from the data store.
      const authenticated = bcryptjs
        .compareSync(credentials.pass, user.password);

      // If the passwords match...
      if (authenticated) 
      {
        // Then store the retrieved user object on the request object
        // so any middleware functions that follow this middleware function
        // will have access to the user's information.
        req.currentUser = user;
      } 
      else 
      {
        message = `Authentication failurer for username: ${user.username}`;
      }
    } 
    else 
    {
        message = `User not found for username: ${credentials.name}`;
    }
  }
  else {
    message = `Auth header not found`;
  }

  // If user authentication failed...
  if (message) {
    console.warn(message);

    // Return a response with a 401 Unauthorized HTTP status code.
    res.status(401).json({ message: 'Access Denied' });
  } else {
    // Or if user authentication succeeded...
    // Call the next() method.
    next();
  }
};

// Getting current authenticated user
router.get('/users', authenticateUser, (req, res) => {
  const user = req.currentUser;

  res.json({
    name: `${user.firstName} ${user.lastName}`,
    email: `${user.emailAddress}`,
  });
});

// Creates a user, sets the Location header to "/" and returns no content
router.post('/users', [
  check('firstName')
    .exists()
    .withMessage('firstName is needed'),
  check('emailAddress')
    .exists()
    .withMessage('Email is needed')
    .isEmail()
    .withMessage('Valid email address for "email"'),
  check('lastName')
    .exists()
    .withMessage('Lastname needed')
], asyncHandler(async (req,res) => {
  const errors = validationResult(req);

  if(!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);
    res.status(400).json({ errors: errorMessages });
  }
  else {
    let user;
    try{
      console.log(req.body);
      user = await User.create(req.body);
      res.status(201).end();
    }
    catch (error)
    {
      if(error.name === "SequelizeValidationError")
      {
        res.status(400).json({answer: "Sequelize it yo"});
      }
    }
  }
}));

module.exports = router;