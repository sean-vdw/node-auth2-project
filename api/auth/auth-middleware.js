const { JWT_SECRET } = require("../secrets"); 
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: 'Token invalid' });
      } else {
        req.decodedJwt = decoded;
        next();
      }
    })
  } else {
    next({ status: 401, message: 'Token required' });
  };
};

const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: 'This is not for you' });
  };
};


const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body;
    const existing = await Users.findBy({ username });
    if (!existing.length) {
      next({ status: 401, message: 'Invalid credentials' })
    } else {
      next();
    }
  } catch(err) {
    next(err);
  };
};


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
 const user = req.body;
 if (user.role_name === null || user.role_name === undefined || user.role_name.trim() === '') {
  user.role_name = 'student';
  next();
 } else if (user.role_name.trim() === 'admin') {
   next({ status: 422, message: 'Role name can not be admin' });
 } else if (user.role_name.trim().length > 32) {
   next({ status: 422, message: 'Role name can not be longer than 32 chars' });
 } else {
   user.role_name = user.role_name.trim();
   next();
 };
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
