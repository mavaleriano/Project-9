'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const auth = require('basic-auth');
const Course = require("../models").Course;
const User = require("../models").User;
const { check, validationResult } = require('express-validator/check');

// Constructing router instance
const router = express.Router();

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

// Middleware to handle user authentication 
const authenticateUser = async (req, res, next) => {
  let message = null;

  // Parse the user's credentials from the Authorization header.
  const credentials = auth(req);

  // If the user's credentials are available...
  if (credentials) {
    // Attempt to retrieve the user via email by user's "key" from Authorization header
    // by their username (i.e. the user's "key"
    const user = await User.findOne( {where: {emailAddress: credentials.name} });

    // If a user was successfully retrieved from the data store...
    if (user) {
      // Use the bcryptjs npm package to compare the user's password
      // (from the Authorization header) to the user's password
      const authenticated = bcrypt
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

// Gets the list of all available courses
// Below link was used to find that MAGICAL .map and .get that gets all the instances of the model
// https://github.com/dcodeIO/bcrypt.js
router.get('/courses', asyncHandler(async (req, res) => {
  let courses;
  courses = await Course.findAll({ include: [{model: User, attributes: ['firstName', 'lastName', 'emailAddress']}], attributes: ['id', 'title', 'description', 'estimatedTime', 'materialsNeeded'] });
  let fullList = courses.map(course => course.get());
  res.json(fullList).end();
}));

// Gets a specific course according to specified parameter
// Sends extra options to the findByPk function to include the User info and to help exclude password and timestamps
router.get('/courses/:id', asyncHandler(async (req, res) => {
  let course;
  try {
    course = await Course.findByPk(req.params.id, { include: [{model: User, attributes: ['firstName', 'lastName', 'emailAddress']}], attributes: ['id', 'title', 'description', 'estimatedTime', 'materialsNeeded'] });
    if(course)
    {
      res.json(course).end();
    }
    else {
      res.status(404).end();
    }
  }
  catch(error)
  {
    res.status(404).location('/');
  }
}));

// Create new course while authenticating user and setting appropriate user id to course
router.post('/courses', authenticateUser, [
  check('title')
    .exists()
    .withMessage('"title" value is needed'),
  check('description')
    .exists()
    .withMessage('"description" value is needed')
], asyncHandler(async (req, res) => {
  const user = req.currentUser;
  const errors = validationResult(req);

  if(!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);
    res.status(400).json({ errors: errorMessages });
  }
  else {
    let course;
    try{
      req.body.userId = user.id;
      course = await Course.create(req.body);
      
      res.status(201).location('/courses/' + course.id).end();
    }
    catch (error)
    {
      res.status(500).json({ errorName: error.name }); // Returns name of error received
    }
  }
}));

// Updates a specific course
// ********* This will only validate if someone actually bothers to send either a title or description
// This allows for the user to just worry about sending in the data that they actually want to change!
// But as a result, it allows for sending in an empty object because it will update nothing!
// https://express-validator.github.io/docs/validation-chain-api.html
router.put('/courses/:id', authenticateUser, [
  check('title')
    .exists( {checkFalsy: true} ) // Checks to make sure, if the value is being included it isnt an invalid value such as an empty string
    .withMessage('"title" value is needed'),
  check('description')
    .exists( {checkFalsy: true} )
    .withMessage('"description" value is needed')
], asyncHandler(async (req, res) => {
  const user = req.currentUser;
  const errors = validationResult(req);

  if(!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);
    res.status(400).json({ errors: errorMessages });
  }
  else {
    let course;
    try{
      course = await Course.findByPk(req.params.id);
      if (course)
      {
        if (user.id === course.userId)
        {
          await course.update(req.body);
          res.status(204).end();
        }
        else
        {
          res.status(403).json({ AuthorizationError: "You are not authorized to update this file"});
        }
      }
      else
      {
        res.status(404);
      }
    }
    catch (error)
    {
      console.log(error.name);
      console.log(error);
    }
  }
}));

// Deletes selected course, so long as you are authenticated as the user who created the course
router.delete('/courses/:id', authenticateUser, asyncHandler(async (req, res) => {
  const user = req.currentUser;
  let course = await Course.findByPk(req.params.id);
  
  if (course)
  {
    if (user.id === course.userId) // Checks user ids to make sure they match before deleting
    {
      await course.destroy();
      res.status(204).end();
    }
    else
    {
      res.status(403).json({ AuthorizationError: "You are not authorized to delete this file"});
    }
  }
  else
  {
    res.status(403).json({ Course: "Course requested does not exist"});
  }
}));

module.exports = router;