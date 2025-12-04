import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { SwaggerModule } from '@nestjs/swagger';
import { loadSwagger } from './config/swagger.config';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import * as session from 'express-session';
import path = require('path');
import { engine } from 'express-handlebars';
import * as cookieParser from 'cookie-parser';
import { AllExceptionsFilter } from './exceptions/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  // Filtro para excepciones aplicado globalmente
  app.useGlobalFilters(new AllExceptionsFilter());

  app.useStaticAssets(join(__dirname, '..', 'public'));
  app.setBaseViewsDir(join(__dirname, '..', 'src', 'views'));
  app.use(
    session({
      secret: 'secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 3500000,
      },
    }),
  );
  //* npm install express-handlebars
  //* import { engine } from 'express-handlebars';
  app.engine('hbs', engine({ extname: '.hbs' }));
  app.set('view engine', 'hbs');
  app.set('views', './src/views');

  app.use(cookieParser());
  // app.useGlobalFilters(new HttpExceptionGlobal());
  // app.useGlobalPipes(new ValidationPipeGlobal());

  // Resto de la configuración...
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  app.enableCors();
  loadSwagger(app);

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Documentación disponible en http://localhost:${port}/`);
  Logger.log(`Documentación disponible en http://localhost:${port}/api-docs`);
  Logger.log(`Server running on http://localhost:${port}`, 'Bootstrap');
}

bootstrap();
