const express = require("express");
const { renderUserTemplate } = require("../utils/template_helper");

const router = express.Router();

router.post("/render", (req, res) => {
  const result = renderUserTemplate(req.body.template);
  res.send(result);
});

module.exports = router;
