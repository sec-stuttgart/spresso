/*
*
* SPRESSO Single Sign-On System - Relying Party
*
*/

const http = require('http');
const https = require('https');
const fs = require('fs');
const qs = require('querystring');
const crypto = require('crypto');
const cookie = require('cookie');
const url = require('url');
const { htmlEncode } = require('htmlencode');
const HttpsProxyAgent = require('https-proxy-agent');
const { createLogger, format, transports } = require('winston');
// config
const config = require('./config');


const startLoginPath = '/startLogin';
const redirPath = '/redir';
const loginPath = '/login';
const spressoInfoPath = '/.well-known/spresso-info';
const spressoLoginPath = '/.well-known/spresso-login';

const loginSessions = {};
const authenticatedSessions = {};


// logging
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: [
    new transports.Console({ format: format.simple() }),
    // new transports.File({ filename: 'combined.log' }),
  ],
});


// use proxy if given
const proxy = config.httpProxy || process.env.httpProxy;
const agent = proxy ? new HttpsProxyAgent(proxy) : null;


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

function serve404(req, res) {
  res.writeHead(404);
  res.write('Not found.');
  res.end();
}

function serveStartLogin(req, res) {
  if (req.method !== 'POST') {
    serve404(req, res);
    return;
  }
  if (req.headers.origin !== undefined && req.headers.origin !== config.rpOrigin) {
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
    const { email } = post;
    const match = email.match(/^[^#&]+@([a-zA-Z0-9-.]+)$/);

    if (match == null) {
      logger.error(`email address does not look valid: ${email}`);
      serve404(req, res);
      return;
    }

    const domain = match[1];

    https.get({
      hostname: domain,
      rejectUnauthorized: false, // Enable for strict checking of SSL outside of test environment.
      path: spressoInfoPath,
      agent,
    }, (xhrres) => {
      let wkResponse = '';

      xhrres.on('data', (chunk) => {
        wkResponse += chunk.toString('ascii');
      });

      xhrres.on('end', () => {
        const idpWk = JSON.parse(wkResponse);

        const rpNonce = createNonce(32);
        const loginSessionToken = createNonce(32);
        const iaKey = createNonce(32);
        const tagKey = createNonce(32);
        const tagIv = createNonce(12);

        const tag = JSON.stringify({ rpNonce, rpOrigin: config.rpOrigin });

        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer(tagKey, 'base64'), Buffer(tagIv, 'base64'));
        const ciphertext = Buffer.concat([cipher.update(tag, 'ascii'), cipher.final(), cipher.getAuthTag()]);

        const tagEnc = JSON.stringify({ iv: tagIv, ciphertext: ciphertext.toString('base64') });

        loginSessions[loginSessionToken] = {
          email,
          rpNonce,
          idpWk,
          tagKey,
          iaKey,
          tagEnc,
          ld_path: `https://${domain}${spressoLoginPath}`,
        };

        const response = JSON.stringify({ forwarderDomain: config.forwarderDomain, loginSessionToken, tagKey });

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': response.length,
        });
        res.write(response);
        res.end();
      });
    });
  });
}

function serveRedir(req, res) {
  const urlParts = url.parse(req.url, true);
  const { loginSessionToken } = urlParts.query;

  if (loginSessions[loginSessionToken] === undefined) {
    serve404(req, res);
    return;
  }

  const loginSession = loginSessions[loginSessionToken];
  const loginUrl = `${loginSession.ld_path}#${loginSession.tagEnc}&${loginSession.email}&${loginSession.iaKey}&${config.forwarderDomain}`;
  const file = fs.readFileSync('static/redir.html');
  const response = file.toString().replace('{{ url }}', htmlEncode(loginUrl));

  res.writeHead(200, {
    'Content-Type': 'text/html',
    'Content-Length': response.length,
  });
  res.write(response);
  res.end();
}


function serveLogin(req, res) {
  if (req.method !== 'POST') {
    serve404(req, res);
    return;
  }
  if (req.headers.origin !== undefined && req.headers.origin !== config.rpOrigin) {
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

    const { loginSessionToken } = post;
    if (loginSessions[loginSessionToken] === undefined) {
      serve404(req, res);
      return;
    }

    const loginSession = loginSessions[loginSessionToken];
    delete loginSessions[loginSessionToken];

    const eiaJson = post.eia;

    // decrypt eia
    const eiaEncrypted = JSON.parse(eiaJson);
    const ivbuf = new Buffer(eiaEncrypted.iv, 'base64');
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      new Buffer(loginSession.iaKey, 'base64'),
      ivbuf.slice(0, 12),
    );
    const ciphertext = new Buffer(eiaEncrypted.ciphertext, 'base64');
    decipher.setAuthTag(ciphertext.slice(-16));
    const _ia = decipher.update(ciphertext.slice(0, -16));
    const _ia2 = decipher.final();
    const iaJson = _ia.toString('ascii') + _ia2.toString('ascii');
    logger.debug('iaJson', iaJson);
    const ia = JSON.parse(iaJson);

    const expectedSigned = {
      tag: loginSession.tagEnc,
      email: loginSession.email,
      forwarderDomain: config.forwarderDomain,
    };

    const expectedSignedJson = JSON.stringify(expectedSigned);

    const wk = loginSession.idpWk;

    // check ia signature
    const verify = crypto.createVerify('RSA-SHA256');
    verify.write(expectedSignedJson);
    if (!verify.verify(wk.public_key, ia.ia_signature, 'base64')) {
      logger.error('ia signature invalid');
      serve404(req, res);
      return;
    }
    logger.info('ia signature valid');

    const authenticatedSessionId = createNonce(32);
    authenticatedSessions[authenticatedSessionId] = loginSession.email;

    const response = loginSession.email;
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': response.length,
      'Set-Cookie': cookie.serialize(
        'authenticatedSessionId',
        authenticatedSessionId, {
          secure: true,
          httpOnly: true,
        },
      ),
    });
    res.write(response);
    res.end();
  });
}

function serveIndex(req, res) {
  const file = fs.readFileSync('static/index.html');
  const response = file.toString();

  res.writeHead(200, {
    'Content-Type': 'text/html',
    'Content-Length': response.length,
  });
  res.write(response);
  res.end();
}

function serveWait(req, res) {
  const file = fs.readFileSync('static/wait.html');
  const response = file.toString();

  res.writeHead(200, {
    'Content-Type': 'text/html',
    'Content-Length': response.length,
  });
  res.write(response);
  res.end();
}


http.createServer((req, res) => {
  const urlParts = url.parse(req.url, true);

  if (urlParts.pathname === '/') {
    serveIndex(req, res);
  } else if (urlParts.pathname === '/wait') {
    serveWait(req, res);
  } else if (urlParts.pathname === startLoginPath) {
    serveStartLogin(req, res);
  } else if (urlParts.pathname === redirPath) {
    serveRedir(req, res);
  } else if (urlParts.pathname === loginPath) {
    serveLogin(req, res);
  } else {
    serve404(req, res);
  }
}).listen(config.listenPort);

logger.info(`spresso relaying party. listening on ${config.listenPort}`);
