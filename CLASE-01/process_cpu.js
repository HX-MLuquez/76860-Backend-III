// CPU Usage Example

// Vamos a inicializar con un bucle según la cantidad de CPU que tenga el sistema

//! ╔══════════════════════════════════════════════════╗
//* ║═════════════════                ═════════════════║
//* ║   >>>   🔵🟢🔵   CODIGO AQUÍ   🔵🟢🔵   <<<   ║
//* ║═════════════════                ═════════════════║
//! ╚══════════════════════════════════════════════════╝

const { cpus } = require("os")


/*
$ node process_cpu.js
Número de CPUs disponibles: 8
Iniciando proceso N° 1 CPU 1
Iniciando proceso N° 2 CPU 2
Iniciando proceso N° 3 CPU 3
Iniciando proceso N° 4 CPU 4
Iniciando proceso N° 5 CPU 5
Iniciando proceso N° 6 CPU 6
Iniciando proceso N° 7 CPU 7
Iniciando proceso N° 8 CPU 8
*/