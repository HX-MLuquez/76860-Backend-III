
var nombre: string = "Juan"
var listStudents: string[] = ["Ana", "Luis", "Carlos"]

nombre = "101" // Error: Type 'number' is not assignable to type 'string'

function sumar(numA: number, numB: number): any {
    return numA + numB
}


/*

Para ejecutar el archivo de TypeScript, primero debemos compilarlo a JavaScript usando el comando:
tsc test.ts
Luego, podemos ejecutar el archivo JavaScript resultante con Node.js usando el comando:
node test.js

*/