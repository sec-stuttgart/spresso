// IDP PORT 9997

"use strict";

var http = require('http');
var fs = require('fs');
var crypto = require('crypto');
var qs = require('querystring');
var cookie = require('cookie');


var public_key_pem = fs.readFileSync('static/serverkey.pub.pem');
var private_key_pem = fs.readFileSync('static/serverkey.priv.pem');
var ld_path = "/.well-known/spresso-login";
var sign_path = "/sign";
var well_known_path = '/.well-known/spresso-info';

var idp_origin = 'https://idp.spresso.me';

var users = {
    'alice@idp.spresso.me': 'alice',
    'bob@idp.spresso.me': 'bob',
}

var sessions = {};

function createNonce(){
    try {
	var buf = crypto.randomBytes(256);
	return buf.toString('base64');
    } catch (ex) {
	console.error("Unable to create nonce.");
	process.exit(-1);
    }
}

function serveStaticFile(filename, res) {
    var stats = fs.statSync(filename);
    
    res.writeHead(200, {
		  'Content-Type': 'text/html',
		  'Content-Length': stats["size"]
		 });
    var fileStream = fs.createReadStream(filename);
    fileStream.pipe(res);
}

function serveWellKnown(res) {
    var wk = JSON.stringify({
	"public_key": public_key_pem.toString('ascii')
    });
    res.writeHead(200, {
	'Content-Type': 'application/json',
	'Content-Length': wk.length
    });
    res.write(wk);
    res.end();
}

function sign(msg) {
    var sign = crypto.createSign('RSA-SHA256');
    sign.write(msg);
    return sign.sign(private_key_pem, 'base64');

}

function getCookies(req) {
    if (req.headers.cookie == undefined) {
	return {};
    }
    return cookie.parse(req.headers.cookie);
}

function getSession(req) {
    var cookies = getCookies(req);
    if (cookies.SESSION_ID == undefined) {
	return {};
    }
    var session_id = cookies.SESSION_ID;
    if (sessions[session_id] == undefined) {
	return {};
    }
    return sessions[session_id];
}

function serveSign(req, res) {
    if (req.method != 'POST') {
	serve404(req, res);
	return;
    }
    if (req.headers.origin !== undefined && req.headers.origin !== idp_origin) {
	console.log('detected XSRF (Origin Header mismatch)');
	serve404(req, res);
	return;
    }

    var body = '';
    req.on('data', function (data) {
        body += data;
        if (body.length > 1e6)
            req.connection.destroy();
    });
    req.on('end', function () {
        var post = qs.parse(body);
	
	var cookies = getCookies(req);

	var logged_in_as = getSession(req).email;
	console.log('logged_in_as '+logged_in_as);
	console.log('postemail '+post['email']);

	if( post['email'] !== logged_in_as &&
	  post['password'] !== users[post['email']]) {
	    console.log('user '+post['email'] + ' is not logged in or has not provided the correct password');
	    res.writeHead(401);
	    res.write('Unauthorized.');
	    res.end();
	    return;
	}

	var to_sign = JSON.stringify({
	    'tag': post['tag'],
	    'email': post['email'],
	    'forwarder_domain': post['forwarder_domain'],
	});
	var response = JSON.stringify({
	    'ia_signature': sign(to_sign)
	});

	var session_id = createNonce(); // when are sessions invalidated???
	sessions[session_id] = {
	    email: post['email'],
	};

	res.writeHead(200, {
	    'Content-Type': 'application/json',
	    'Content-Length': response.length,
	    'Set-Cookie': cookie.serialize(
		'SESSION_ID',
		session_id,
		{
		    secure: true,
		    httpOnly: true,
		}),
	});
	res.write(response);
	res.end();
    });
}

function serveLoginDialog(req, res) {
    var session = getSession(req);
    var email = (session == undefined) ? '' : session.email;
    
    var file = fs.readFileSync('static/ld.html');
    var response = file.toString().replace('{{ email }}',email);
    
    res.writeHead(200, {
	'Content-Type': 'text/html',
	'Content-Length': response.length,
    });
    res.write(response);
    res.end();
}

function serve404(req, res) {
    res.writeHead(404);
    res.write('Not found.');
    res.end();
}

http.createServer(function(req, res) {
    console.log('REQUEST',req.url,req.headers);
    if (req.url == well_known_path) {
	serveWellKnown(res);
    } else if (req.url == ld_path) {
	serveLoginDialog(req, res);
    } else if (req.url == sign_path) {
	serveSign(req, res);
    } else {
	serve404(req, res);
    }

}).listen(9997);
