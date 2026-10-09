const express = require("express");
const lodash = require("lodash");

const app = express();

app.post("/execute", (req, res) => {
  const action = req.body.action;
  const result = lodash[action](req.body.payload);
  res.json({ result });
});

app.listen(3000);
