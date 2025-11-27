# NEST

## Verificar versión de nest
nest --version

## Instalación
npm i -g @nestjs/cli

## Iniciar API con nest
nest new api-university

## Modelo de Negocio 

### Entidades o Models 
- Student
- Course
- Subject (Materias)
- Enrollment (Matricula)
- Professor
- Department



## Nuevo módulo

nest g resource modules/products

nest g resource students
nest g resource courses
nest g resource professors
nest g resource departments


---

# Parte 2

- ts
  - entity
  - dto
- decoradores
- Hacer pequeño crud
- integrar config (.env)
- integrar mongo

## Para DB MOngo mongoose
npm i mongoose @nestjs/mongoose

## Para variables de entorno
npm i @nestjs/config 
