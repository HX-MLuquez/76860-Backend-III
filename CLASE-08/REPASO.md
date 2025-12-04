hola

1. ¿Que es NEST?
Francisca Bahamondes Walters 11:38
un framework para hacer apps

Amir Kalasnicoy  to  Everyone 11:38
un framework para construir aplicaciones backend

Diego Di Lonardo 11:38
1 - Es un Framework

Framework -> JS <- 
core NEST -> 
    TS + Express + POO + Escalable + Muy modular muy estructurado + MODULOS 

2. ¿Como utilizar?
Documentación oficial 
Instalar globalmente nest cli 

Usar NPM o YARN
npm i -g @nestjs/cli

nest new nombre-proyecto

Recursos - Entidades 
Nuevo recurso User
nest g resource user

main.ts -> a nuestras necesidades

APP.MODULE.ts -> Módulo raíz donde se implementan los demás módulos
y la mayoría de las configuraciones globales

3. ¿Por que usar o parender NEST?

Diego Di Lonardo 11:48
es un plus para trabajos de BACK END

Francisca Bahamondes Walters 11:48
da estructura, es escalable
     |

Amir Kalasnicoy 11:49
está bien estructurado, es escalable y usa TypeScript

Francisca Bahamondes Walters 11:49
facilita el trabajo en equipo +++ <- homogénea

Diego Di Lonardo 11:49
es una forma homogénea para que cualquier programador le sea mas facil tomar este tipo de estructuras en NEST


la Moda - 


---


Supertest -> testing de endpoints - de integración 

const supertest = require('supertest');
const app = require('../app'); // Ruta a tu aplicación Express

const request = supertest(app);

Es una instancia de nuestro servidor para hacer peticiones HTTP en los tests
Es un objeto instancia test de nuestro server
request {
    get 
    post
    put
    delete

    etc.
}


---

Contenedores - Docker

1. ¿Que es un contenedor?
es un lugar donde se alojan imagenes de configuraciones especificas de CPU, MEMORIA, SOFT, ETC?
te juro que no

Aldo Zunino Becerra  to  Everyone 12:30
es paquete que incluye todo lo necesario para correr una api

Francisca Bahamondes Walters 12:30
como una caja que contiene la app para que funcione en cualquier lugar, en verdad no sé como expicarlo no lo tengo tan claro


Aldo Zunino Becerra  to  Everyone 12:31
claro sisi era mas una deficinion muy base

2. ¿Para que sirve?
3. ¿Por que usarlo?
4. ¿Como usar Docker?

1. Crear el Dockerfile 
Dame sistema Linux x
FROM node:20.11.0
Dame npm x
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY ./src ./src
EXPOSE 8080
CMD ["npm", "start"]

Por defecto el contenedor 
tiene un sistema operativo Linux, por lo que si queremos correr una app de Node.js, debemos especificar la imagen base de Node.js que queremos usar. 

2. Crear la imagen
docker build -t nombre-imagen .

3. Crear el contenedor (y correrlo)
docker run -d -p 8080:8080 nombre-imagen


Me gusta pensar el contenedor como máquinas contenedoras que tienen todo lo necesario para ejecutar una aplicación, incluyendo el código, las dependencias y la configuración del entorno.


Orquestación - Kubernetes
1. ¿Que es Kubernetes?
Es un sistema de orquestación de contenedores que permite automatizar la implementación, escalado y gestión de aplicaciones en contenedores. Y trabaja con CLusteres de contenedores, que son grupos de nodos (máquinas) que ejecutan aplicaciones en contenedores.






---

Después de la pausa

- Proyecto Integrador en versión NEST muy brevemente 
- Desplegar en Render 
- Repasar conceptos sobre el Trabajo Final
