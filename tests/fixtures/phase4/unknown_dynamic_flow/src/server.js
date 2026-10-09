const express = require("express");
const lodash = require("lodash");

const app = express();
app.use(express.json());

app.post("/dynamic", (req, res) => {
  // Dynamic property access on request object prevents static determination
  const key = req.headers["x-dynamic-key"];
  const dynamicInput = req.body[key];
  const compiled = lodash.template(dynamicInput);
  res.send(compiled());
});

app.listen(3000);
