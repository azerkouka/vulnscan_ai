// DELIBERATELY VULNERABLE - sample input for the scanner. Never run or deploy.

const express = require('express');

const app = express();

app.get('/calc', (req, res) => {
  // VULNERABLE: code injection - request input is evaluated as JavaScript.
  const result = eval(req.query.expression);
  res.send(String(result));
});

app.get('/hello', (req, res) => {
  // VULNERABLE: reflected XSS - request input is written into HTML unescaped.
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

app.listen(3000);
