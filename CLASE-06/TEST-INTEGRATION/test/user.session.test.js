import { expect } from "chai";
import { describe, it, before, after } from "mocha";

import supertest from "supertest";
import mongoose from "mongoose";
import app from "../src/app.js";

mongoose.set("strictQuery", true);

// URL de conexión a la base de datos de testing
const MONGO_URI =
  "mongodb://localhost:27017/integration_testing?directConnection=true";

// Instancia de supertest apuntando a tu servidor
// const request = supertest("http://localhost:8080");
//* CODE AQUI:

//* request {} <- es nuestro Servidor Test <---- request===appServerTest

describe("Testing users Api", function () {
  
});

/*
requestSupertestServerCloneMoreTest {
  métodos
  routes de nuestra app
}

describe{

    conectado a la base de datos
    mockUser {}
    cookie null 
}




npm test 

describe {


}
before -> conectar a la base de datos
describe {
mockUser: {
      first_name: "Usuario de prueba 2",
      last_name: "Apellido de prueba 2",
      email: "correodeprueba2@gmail.com",
      password: "123456",
    };
cookie: null;
}


* SERVER 
app {
get /api/sessions/register  
post /api/sessions/login
post /api/pets/withimage
get: function(){...} 
use: function(){...}
listen: function(){...}
...
}

---> requestSUPERTEST 
requestSupertestServerCloneMoreTest {
get /api/sessions/register  
post /api/sessions/login
post /api/pets/withimage
get: function(){...} 
use: function(){...}
listen: function(){...}
...
+ métodos para testear que implementa supertest
+ - .get()
+ - .post()
+ - .put()
+ - .delete()
+ - .set()
+ - .expect()
+ - .send()
+ - .attach()
...
}
*/
