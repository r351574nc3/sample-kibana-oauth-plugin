const _ = require('lodash');
const Boom = require('boom');
const Joi = require('joi');

export default (server) => {
  server.route({
    method: 'POST',
    path: '/api/security/v2/login',
    handler(request, reply) {
      const {username, password} = request.payload;
      return isValidUser(request, username, password).then((response) => {
        // Initialize the session
        request.cookieAuth.set({
          username,
          password,
          expires: Date.now() + 90000
        });

        return reply(response);
      }, (error) => {
        request.cookieAuth.clear();
        return reply(Boom.unauthorized(error));
      });
    },
    config: {
      auth: false,
      validate: {
        payload: {
          username: Joi.string().required(),
          password: Joi.string().required()
        }
      }
    }
  });