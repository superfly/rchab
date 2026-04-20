const http = require('http');

const port = process.env.PORT || 3000;

http.createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('Hello from rchab buildpacks test\n');
}).listen(port, () => {
  console.log(`listening on :${port}`);
});
