const minimist = require("minimist");

function runCli() {
  const args = minimist(process.argv.slice(2));
  console.log("Parsed CLI args:", args);
}

runCli();
