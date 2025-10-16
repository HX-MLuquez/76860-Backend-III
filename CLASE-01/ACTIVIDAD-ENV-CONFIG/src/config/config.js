//! ╔══════════════════════════════════════════════════╗
//* ║═════════════════                ═════════════════║
//* ║   >>>   🔵🟢🔵   CODIGO AQUÍ   🔵🟢🔵   <<<   ║
//* ║═════════════════                ═════════════════║
//! ╚══════════════════════════════════════════════════╝
const { Command, Option } = require("commander");
const program = new Command();

/*
program.option("-p, --port <PORT>", "Puerto donde escuchará el server", 3000)
program.option("-c, --color <COLOR>", "Color de fondo...")
program.option("-d, --debug", "Activa mode debug")
program.option("-h, --heroes [heroes...]", "Listado heroes")
program.requiredOption("-t, --theme <THEME>", "Tema de fondo")
program.addOption(new Option("-m, --mode <MODE>", "Modo de ejecución del script").choices(["prod", "dev", "test"]).default("prod"))
*/
program.option("-p, --port <PORT>", "Puerto donde escuchará el server", 3000)
program.option("-c, --color <COLOR>", "Color de fondo...")
program.addOption(
  new Option("-m, --mode <MODE>", "Modo de ejecución del server")
    .choices(["prod", "dev"])
    .default("dev")
);

/*

program -> argumentos {

p o port: 3000,
c o color: undefined,
m o mode: "dev" <- solo puede ser 'prod' o 'dev'

}

*/
program.allowUnknownOption(); // node index.js --debug dev <- program -> arguments.debug X Error
program.allowExcessArguments(); // node index.js arg1 ... arg2 ... arg3 ... arg4...  X Error

program.parse();
console.log(program.opts()); //* OPTS <- tenemos el objeto ARGUMENTS
/*
node index.js --mode dev --port 3001
{ port: '3001', mode: 'dev' }

node index.js --mode prod --port 8080
{ port: '8080', mode: 'prod' }
*/

const { mode } = program.opts();
//  { mode: 'prod' }

process.loadEnvFile(mode === "prod" ? "./.env.prod" : "./.env.dev");

const config = {
  PORT: process.env.PORT,
  SECRET: process.env.SECRET,
};

module.exports = { config };