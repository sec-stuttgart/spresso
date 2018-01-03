/*
*
* SPRESSO Single Sign-On System - Identity Provider
*
*/

const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const qs = require('querystring');
const cookie = require('cookie');
const { createLogger, format, transports } = require('winston');
// config
const config = require('./config');


const publicKeyPem = fs.readFileSync(config.tls.publicKeyPem);
const privateKeyPem = fs.readFileSync(config.tls.privateKeyPem);
const ldPath = '/.well-known/spresso-login';
const signPath = '/sign';
const wellKnownPath = '/.well-known/spresso-info';

const sessions = {};

// logging
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: [
    new transports.Console({ format: format.simple() }),
    // new transports.File({ filename: 'combined.log' }),
  ],
});

function createNonce(length) {
  try {
    const buf = crypto.randomBytes(length);
    const nonce = buf.toString('base64');
    return nonce;
  } catch (ex) {
    logger.error('Unable to create nonce.');
    process.exit(-1);
    return false;
  }
}

// function serveStaticFile(filename, res) {
//   const stats = fs.statSync(filename);
//
//   res.writeHead(200, {
//     'Content-Type': 'text/html',
//     'Content-Length': stats.size,
//   });
//   const fileStream = fs.createReadStream(filename);
//   fileStream.pipe(res);
// }

function serveWellKnown(res) {
  const wk = JSON.stringify({
    public_key: publicKeyPem.toString('ascii'),
  });
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Length': wk.length,
  });
  res.write(wk);
  res.end();
}

function sign(msg) {
  const msgSign = crypto.createSign('RSA-SHA256');
  msgSign.write(msg);
  return msgSign.sign(privateKeyPem, 'base64');
}

function getCookies(req) {
  if (req.headers.cookie === undefined) {
    return {};
  }
  return cookie.parse(req.headers.cookie);
}

function getSession(req) {
  const cookies = getCookies(req);
  if (cookies.sessionId === undefined) {
    return {};
  }
  const { sessionId } = cookies;
  if (sessions[sessionId] === undefined) {
    return {};
  }
  return sessions[sessionId];
}

function serve404(req, res) {
  res.writeHead(404);
  res.write('Not found.');
  res.end();
}

function serveSign(req, res) {
  if (req.method !== 'POST') {
    serve404(req, res);
    return;
  }
  if (req.headers.origin !== undefined && req.headers.origin !== config.idpOrigin) {
    logger.warn('detected XSRF (Origin Header mismatch)');
    serve404(req, res);
    return;
  }

  let body = '';
  req.on('data', (data) => {
    body += data;
    if (body.length > 1e6) { req.connection.destroy(); }
  });

  req.on('end', () => {
    const post = qs.parse(body);
    // const cookies = getCookies(req);

    const loggedInAs = getSession(req).email;
    logger.debug(`loggedInAs ${loggedInAs}`);
    logger.debug(`postemail ${post.email}`);

    if (post.email !== loggedInAs && post.password !== config.users[post.email]) {
      logger.warn(`user ${post.email} is not logged in or has not provided the correct password`);
      res.writeHead(401);
      res.write('Unauthorized.');
      res.end();
      return;
    }

    const toSign = JSON.stringify({
      tag: post.tag,
      email: post.email,
      forwarder_domain: post.forwarder_domain,
    });
    const response = JSON.stringify({ ia_signature: sign(toSign) });

    // when are sessions invalidated???
    const sessionId = createNonce(256);
    sessions.sessionId = { email: post.email };

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': response.length,
      'Set-Cookie': cookie.serialize(
        'sessionId',
        sessionId,
        {
          secure: true,
          httpOnly: true,
        },
      ),
    });
    res.write(response);
    res.end();
  });
}

function serveLoginDialog(req, res) {
  const session = getSession(req);
  const email = (session === undefined) ? '' : session.email;

  const file = fs.readFileSync('static/ld.html');
  const response = file.toString().replace('{{ email }}', email);

  res.writeHead(200, {
    'Content-Type': 'text/html',
    'Content-Length': response.length,
  });
  res.write(response);
  res.end();
}


http.createServer((req, res) => {
  logger.debug('REQUEST', req.url, req.headers);
  if (req.url === wellKnownPath) {
    serveWellKnown(res);
  } else if (req.url === ldPath) {
    serveLoginDialog(req, res);
  } else if (req.url === signPath) {
    serveSign(req, res);
  } else {
    serve404(req, res);
  }
}).listen(config.listenPort);

logger.info(`spresso identity provider started. listening on ${config.listenPort}`);
