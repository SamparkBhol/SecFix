const express = require("express");
const { exec } = require("child_process");
const app = express();

app.use(express.json());

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, out) => {
    res.send(out);
  });
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hi " + req.query.name + "</h1>");
});

app.post("/calc", (req, res) => {
  const r = eval(req.body.expr);
  res.json({ result: r });
});

app.listen(3000);
