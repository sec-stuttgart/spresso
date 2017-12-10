/*
*
* SPRESSO Single Sign-On System - Forwarder
*
*/

const http = require('http');
const fs = require('fs');
const { createLogger, format, transports } = require('winston');
// config
const config = require('./config');


// logging
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: [
    new transports.Console({ format: format.simple() }),
    // new transports.File({ filename: 'combined.log' }),
  ],
});


function serveStaticFile(filename, res) {
  const stats = fs.statSync(filename);

  res.writeHead(200, {
    'Content-Type': 'text/html',
    'Content-Length': stats.size,
  });
  const fileStream = fs.createReadStream(filename);
  fileStream.pipe(res);
}

http.createServer((req, res) => {
  serveStaticFile('static/index.html', res);
}).listen(config.listenPort);

logger.info(`spresso forwarder started. listening on ${config.listenPort}`);
