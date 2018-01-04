'use strict';

const getClient = require('../../../x-pack/plugins/security/server/lib/get_client_shield');

export default function getUserProvider(server) {
  const callWithRequest = getClient(server);

  server.plugins.security.getUser = function(request) {
    const xpackInfo = server.plugins.xpack_main.info;
    if (xpackInfo && xpackInfo.isAvailable() && !xpackInfo.feature('security').isEnabled()) {
      return Promise.resolve(null);
    }
    return callWithRequest(request, 'shield.authenticate');
  };
};

/*
const get_is_valid_user = require('../../../x-pack/plugins/security/server/lib/get_is_valid_user');

exports = module.exports = get_is_valid_user.default = (server) => {

server.plugins.security.getUser = function(request) {
    const xpackInfo = server.plugins.xpack_main.info;
    if (xpackInfo && xpackInfo.isAvailable() && !xpackInfo.feature('security').isEnabled()) {
      return Promise.resolve(null);
    }
    return callWithRequest(request, 'shield.authenticate');
};

exports = module.exports = get_is_valid_user.default = (server) => {
    return function isValidUser(request, username, password) {
        // assign(request.headers, basicAuth.getHeader(username, password));
        // return server.plugins.security.getUser(request);
        console.log("[debug]", "Hey! The gang's all here!");
        return true;
    };
}; // original function */