'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const auth = require('basic-auth');
const Course = require("../models").Course;
const User = require("../models").User;

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

// https://github.com/dcodeIO/bcrypt.js
router.get('/courses', asyncHandler(async (req, res) => {
  let courses;
  courses = await Course.findAll({include: [{model: User}] });
  let again = courses.map(course => course.get());
  res.json(again).end();
}));

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



module.exports = router;