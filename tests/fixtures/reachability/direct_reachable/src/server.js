const express = require("express");
const lodash = require("lodash");

const app = express();

app.get("/render", (req, res) => {
  const compiled = lodash.template(req.query.tpl);
  res.send(compiled());
});

app.listen(3000);
