const express = require("express");
const lodash = require("lodash");

const app = express();

app.get("/items", (req, res) => {
  // Uses safe utility functions, never invokes vulnerable template()
  const items = [1, 2, 3, 4];
  const doubled = lodash.map(items, x => x * 2);
  res.json(doubled);
});

app.listen(3000);
