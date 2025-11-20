//* MOCHA + CHAI


// *1. npm install mocha chai --save-dev
// *2. Agregar en package.json el script:
// * "test": "mocha ./test/**/*.test.js --exit"
// *3. Ejecutar los test con: npm test
//* al ejecutar npm test se buscan todos los archivos que terminen en .test.js dentro de la carpeta test y subcarpetas
//* no es necesario importar los métodos de mocha (describe, it, before, after, etc), pero se hace para tener autocompletado en el editor
//* En los test se implementa mucho las funciones callback

// *4. Creamos una serie de test unitarios para el DAO de Users utilizando Chai para las aserciones

import Users from "../src/dao/Users.dao.js";
// class Users {
//   constructor() {
//     this.users = [];
//     this.currentId = 1;
//   }
//   async save(user) {}
//   async get(filter) {}
//   async getBy(filter) {}
//   async update(id, data) {}
//   async delete(id) {}
// }

import mongoose from "mongoose";

//* Importamos Chai para las aserciones
import { expect } from "chai";

// import { describe, it, before, after, beforeEach, afterEach } from "mocha";

// describe <-- Grupo de pruebas
// it or test <-- Prueba individual (Test en sí)

import dotenv from "dotenv";
dotenv.config();
const { MONGO_URI } = process.env;

before(async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("Conexión a la base de datos exitosa.");
  } catch (error) {
    console.error(`Error al conectar a la base de datos: ${error.message}`);
  }
});

describe("Test unitarios CRUD para el DAO del Users con MOCHA + CHAI", function () {
 
});
