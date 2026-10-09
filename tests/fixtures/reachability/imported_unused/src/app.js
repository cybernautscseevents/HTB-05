const express = require("express");
const lodash = require("lodash");

const app = express();

app.get("/clean", (req, res) => {
  const cleanStr = lodash.escape(req.query.input);
  res.send(cleanStr);
});

app.listen(3000);
