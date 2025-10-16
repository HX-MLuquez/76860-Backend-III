// PROCESS CHILD
//* Proceso hijo que realiza un cálculo complejo

// ---
//! ╔══════════════════════════════════════════════════╗
//* ║═════════════════                ═════════════════║
//* ║   >>>   🔵🟢🔵   CODIGO AQUÍ   🔵🟢🔵   <<<   ║
//* ║═════════════════                ═════════════════║
//! ╚══════════════════════════════════════════════════╝
const { calculoComplejo } = require("./functionCompleja.js"); // Importa la función de cálculo complejo

process.on("message", (msg) => {
  console.log(`Proceso hijo (PID ${process.pid}) recibió: "${msg}"`);
  console.log("Comienza cálculo complejo");
  console.time("Duración del cálculo");
  const result = calculoComplejo();
  console.timeEnd("Duración del cálculo");
  /*
    Proceso hijo (PID 1164) recibió: "Iniciar cálculo desde proceso principal PID 1155"
    Comienza cálculo complejo
    Duración del cálculo: 9.244s
  */

  process.send({ type: "resultado", result: Math.round(result) });
});

//* Este es un process HIJO
//* process.on("message")  + process.send

/*

listener("click", ()=>{})

*/
