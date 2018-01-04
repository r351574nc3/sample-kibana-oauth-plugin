const Querystring = require('querystring');
const Bell = require('bell');
const Boom = require('boom');
const uuidv4 = require('uuid/v4');
const Hydra = require('./lib/providers/hydra');
const Wreck = require('wreck');
const winston = require('winston')

const internals = {};

internals.parse = function (payload) {

  payload = Buffer.isBuffer(payload) ? payload.toString() : payload;
  if (payload.trim()[0] === '{') {
    try {
      return JSON.parse(payload);
    }
    catch (err) {
      return err;
    }
  }

  return Querystring.parse(payload);
};

export default function (kibana) {
  return new kibana.Plugin({
    require: ['kibana', 'elasticsearch', 'security'],
    name: 'datapipe-es-oauth',
    uiExports: {

    },
    config(Joi) {
      return Joi.object({
        enabled: Joi.boolean().default(true),
        provider: Joi.string().default('hydra'),
        providerHost: Joi.string(),
        password: Joi.string(),
        clientId: Joi.string(),
        clientSecret: Joi.string(),
        redirectUri: Joi.string(),
        userInfoUrl: Joi.string(),
        internalName: Joi.string(),
        cookieName: Joi.string().default('sid')
      }).default();
    },
    init: function (server, options) {
      const config = server.config();

      server.register([Bell], function (err) {
        if (err) {
          throw err;
        }

        Bell.providers.hydra = Hydra;
        server.auth.strategy(options.provider, 'bell', {
          config: {
            authHost: options.providerHost,
            userInfoUrl: options.userInfoUrl
          },
          location: options.redirectUri,
          password: options.password,
          provider: options.provider,
          clientId: options.clientId,
          clientSecret: options.clientSecret,
          skipProfile: false,
          scope: ['profile']
        });

      });

      // Redirect native login to oauth login. Bypass native kibana login page
      server.ext('onRequest', (req, reply) => {
        if (req.path() == '/login') {
          reply.redirect('/auth/login');
        }
      });
      
      server.route({
        method: ['GET', 'POST'],
        path: '/auth/login',
        config: {
          auth: options.provider
        },
        handler: function (request, reply) {
          console.log('Received OAuth Call back.');
          const credentials = request.auth.credentials;

          if (!request.auth.isAuthenticated) {
            return reply('Authentication failed due to: ' + request.auth.error.message);
          }

          const base64Auth = new Buffer(`${credentials.profile.username}:${credentials.token}`).toString('base64');
          const requestOptions = {
            payload: {
              username: credentials.profile.username,
              password: credentials.token
            },
            headers: {
              'Accept': 'application/json, text/plain, */*',
              'Content-Type': 'application/json;charset=UTF-8',
              'DNT': 1,
              'kbn-name': 'kibana',
              'kbn-version': '5.6.2',
              'Referer': options.redirectUri + '/auth/login',
              'Origin': options.redirectUri,
              'X-Hydra-Authorization': new Buffer(`Basic ${base64Auth}`)
            }
          };

          var response = '';
          const loginUrl = 'http://' + options.internalName + '/api/security/v1/login';
          console.log('Received OAuth Call back - redirecting authentication to XPac Security to url:', loginUrl + ' for user ' + credentials.profile.username);

          Wreck.post(loginUrl, requestOptions, (err, res, payload) => {
            if (err ||
              res.statusCode < 200 ||
              res.statusCode > 299) {
              return reply(Boom.unauthorized('Authorization with elasticsearch failed'));
            }

            response = reply().code(302).header('Location', '/')
              .state('credentials', credentials)

            var sidcookie = '';

            if (res.headers['set-cookie'] !== null
              && res.headers['set-cookie'].length > 0) {
              sidcookie = res.headers['set-cookie'][0];
            }
            response = response.header('Set-Cookie', sidcookie);

            return response;
          });
        }
      });
    }
  });
};

