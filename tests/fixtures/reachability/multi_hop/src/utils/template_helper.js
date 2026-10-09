const lodash = require("lodash");

function renderUserTemplate(input) {
  const compiled = lodash.template(input);
  return compiled();
}

module.exports = {
  renderUserTemplate,
};
