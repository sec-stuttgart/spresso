// RP PORT 9996

var http = require('http');
var https = require('https');
var fs = require('fs');
var qs = require('querystring');
var crypto = require('crypto');
var cookie = require('cookie');
var url = require('url');
var htmlEncode = require('htmlencode').htmlEncode;

var start_login_path = "/startLogin";
var redir_path = "/redir";
var login_path = "/login";
var spresso_info_path = "/.well-known/spresso-info";
var spresso_login_path = "/.well-known/spresso-login";

var login_sessions = {};
var authenticated_sessions = {};

var rp_origin = 'https://rp.spresso.me';
var forwarder_domain = 'fwd.spresso.me';


function createNonce(length){
    try {
	var buf = crypto.randomBytes(length);
	return buf.toString('base64');
    } catch (ex) {
	console.error("Unable to create nonce.");
	process.exit(-1);
    }
}

function serveStartLogin(req, res) {
    if (req.method != 'POST') {
	serve404(req, res);
	return;
    }
    if (req.headers.origin !== undefined && req.headers.origin !== rp_origin) {
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
	var email = post['email'];
	var match = email.match(/^[^#&]+@([a-zA-Z0-9-.]+)$/)

	if (match == null) {
	    console.error("Email address does not look valid: " + email);
	    serve404(req, res);
	    return;
	}

	var domain = match[1];

	https.get({
	    hostname: domain,
	    rejectUnauthorized: false, //Enable for strict checking of SSL outside of test environment.
	    path: spresso_info_path
	}, function (xhrres) { 
	    
	    var wk_response = '';

	    xhrres.on('data', function (chunk) {
		wk_response += chunk.toString('ascii');
	    });

	    xhrres.on('end', function () {
		var wk = JSON.parse(wk_response);

		var rp_nonce = createNonce(32);
		var login_session_token = createNonce(32);
		var ia_key = createNonce(32);
		var tag_key = createNonce(32);
		var tag_iv = createNonce(12);

		var tag = JSON.stringify({
		    rp_nonce: rp_nonce,
		    rp_origin: rp_origin,
		});

		var cipher = crypto.createCipheriv('aes-256-gcm', Buffer(tag_key, 'base64'), Buffer(tag_iv, 'base64'));
		var ciphertext = Buffer.concat(
		    [cipher.update(tag, 'ascii'), 
		    cipher.final(),
		    cipher.getAuthTag()]
		);

		var tag_enc = JSON.stringify({
		    iv: tag_iv,
		    ciphertext: ciphertext.toString('base64')
		});
		
		login_sessions[login_session_token] = {
		    email: email,
		    rp_nonce: rp_nonce,
		    idp_wk: wk,
		    tag_key: tag_key,
		    ia_key: ia_key,
		    tag_enc: tag_enc,
		    ld_path: 'https://' + domain + spresso_login_path,
		};

		var response = JSON.stringify({
		    'forwarder_domain': forwarder_domain,
		    'login_session_token': login_session_token,
		    'tag_key': tag_key
		});
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
    var url_parts = url.parse(req.url, true);
    var login_session_token = url_parts.query.login_session_token;
    console.log(login_session_token);
    console.log(login_sessions);
    if (login_sessions[login_session_token] == undefined) {
	serve404(req, res);
	return;
    }

    var login_session = login_sessions[login_session_token];
    var login_url = login_session.ld_path + "#" 
	+ login_session.tag_enc + '&' 
	+ login_session.email + '&'
	+ login_session.ia_key + '&'
	+ forwarder_domain;
    var file = fs.readFileSync('static/redir.html');
    var response = file.toString().replace('{{ url }}', htmlEncode(login_url));
    
    res.writeHead(200, {
	'Content-Type': 'text/html',
	'Content-Length': response.length,
    });
    res.write(response);
    res.end();
}




function serveLogin(req, res) {
    if (req.method != 'POST') {
	serve404(req, res);
	return;
    }
    if (req.headers.origin !== undefined && req.headers.origin !== rp_origin) {
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

	var login_session_token = post['login_session_token'];
	if (login_sessions[login_session_token] == undefined) {
	    serve404(req, res);
	    return;
	}

	var login_session = login_sessions[login_session_token];
	delete login_sessions[login_session_token];

	var eia_json = post['eia'];
	
	// decrypt eia
	var eia_encrypted = JSON.parse(eia_json);
	var ivbuf = new Buffer(eia_encrypted.iv,'base64')
	var decipher = crypto.createDecipheriv(
	    'aes-256-gcm',
	    new Buffer(login_session.ia_key, 'base64'),
	    ivbuf.slice(0,12)
	);
	var ciphertext = new Buffer(eia_encrypted.ciphertext,'base64');
	decipher.setAuthTag(ciphertext.slice(-16));
	var _ia = decipher.update(ciphertext.slice(0,-16));
	var _ia2 = decipher.final();
	var ia_json = _ia.toString('ascii') + _ia2.toString('ascii');
	console.log('ia_json', ia_json);
	var ia = JSON.parse(ia_json);

	var expected_signed = {
	    'tag': login_session.tag_enc,
	    'email': login_session.email,
	    'forwarder_domain': forwarder_domain,
	};

	var expected_signed_json = JSON.stringify(expected_signed);
	
	var wk = login_session.idp_wk;

	// check ia signature
	var verify = crypto.createVerify('RSA-SHA256');
	verify.write(expected_signed_json);
	if (!verify.verify(wk.public_key, ia.ia_signature, 'base64')) {
	    console.error('ia signature invalid');
	    serve404(req, res);
	    return;
	}
	console.log('ia signature valid');

	var authenticated_session_id = createNonce(32);
	authenticated_sessions[authenticated_session_id] = login_session.email;

	var response = login_session.email;
	res.writeHead(200, {
	    'Content-Type': 'application/json',
	    'Content-Length': response.length,
	    'Set-Cookie': cookie.serialize(
		'AUTHENTICATED_SESSION_ID',
		authenticated_session_id,
		{
		    secure: true,
		    httpOnly: true,
		}),
	});
	res.write(response);
	res.end();
	
    });
}

function serve404(req, res) {
    res.writeHead(404);
    res.write('Not found.');
    res.end();
}

function serveIndex(req, res) {
    var file = fs.readFileSync('static/index.html');
    var response = file.toString();
    
    res.writeHead(200, {
	'Content-Type': 'text/html',
	'Content-Length': response.length,
    });
    res.write(response);
    res.end();
}

function serveWait(req, res) {
    var file = fs.readFileSync('static/wait.html');
    var response = file.toString();
    
    res.writeHead(200, {
	'Content-Type': 'text/html',
	'Content-Length': response.length,
    });
    res.write(response);
    res.end();
}


http.createServer(function(req, res) {

    var url_parts = url.parse(req.url, true);

    if(url_parts.pathname == '/') {
	serveIndex(req, res);
    } else if(url_parts.pathname == '/wait') {
	serveWait(req, res);
    } else if (url_parts.pathname == start_login_path) {
	serveStartLogin(req, res);
    } else if(url_parts.pathname == redir_path) {
	serveRedir(req, res);
    } else if (url_parts.pathname == login_path) {
	serveLogin(req, res);
    } else {
	serve404(req, res);
    }

}).listen(9996);
