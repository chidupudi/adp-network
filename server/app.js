const express = require('express');
const app = express();
const port = 3001;

app.get('/', (req, res) => {
  console.log(`Request from IP: ${req.ip}`);
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`App running at http://localhost:${port}`);
});
