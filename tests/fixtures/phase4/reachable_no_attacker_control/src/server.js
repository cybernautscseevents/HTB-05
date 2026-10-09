const express = require("express");
const lodash = require("lodash");

const app = express();
const STATIC_TEMPLATE = "<h1>System Status: Operational</h1>";

app.get("/status", (req, res) => {
  // Reachable from route, but calls template with an internal static constant
  const compiled = lodash.template(STATIC_TEMPLATE);
  res.send(compiled());
});

app.listen(3000);
