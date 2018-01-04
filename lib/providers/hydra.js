'use strict';

const Querystring = require('querystring');
const Url = require('url');
const Boom = require('boom');
const Cryptiles = require('cryptiles');
const Crypto = require('crypto');
const Hoek = require('hoek');
const Wreck = require('wreck');

const internals = {};

exports = module.exports = function (options) {
    options = options || {};

    return {
        name: 'hydra',
        protocol: 'oauth2',
        useParamsAuth: false,
        auth: 'https://' + options.authHost + '/oauth2/auth',
        token: 'https://' + options.authHost + '/oauth2/token',
        scope: ['profile'],
        profile: function (credentials, params, get, callback) {
            get(options.userInfoUrl, null, (profile) => {
                credentials.profile = {
                    username: profile.username,
                    displayName: profile.name,
                    groups: profile.groups,
                    email: profile.email,
                    raw: profile
                };
                return callback();
            });
        }
    };
};