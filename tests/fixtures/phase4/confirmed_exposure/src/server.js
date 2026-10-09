const express = require("express");
const lodash = require("lodash");

const app = express();
app.use(express.json());

app.post("/render", (req, res) => {
  const template = req.body.template;
  const compiled = lodash.template(template);
  res.send(compiled());
});

app.listen(3000);
