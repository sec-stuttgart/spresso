// FWD PORT 9998

var http = require('http');
var fs = require('fs');

function serveStaticFile(filename, res) {
    var stats = fs.statSync(filename);
    
    res.writeHead(200, {
		  'Content-Type': 'text/html',
		  'Content-Length': stats["size"]
		 });
    var fileStream = fs.createReadStream(filename);
    fileStream.pipe(res);
}

http.createServer(function(req, res) {

    serveStaticFile('static/index.html',res);
    return;
  

}).listen(9998);
