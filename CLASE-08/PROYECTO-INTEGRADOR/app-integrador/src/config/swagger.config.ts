import { INestApplication } from '@nestjs/common';
import { SwaggerModule } from '@nestjs/swagger';
import * as fs from 'fs';
import * as yaml from 'yaml';

export function loadSwagger(app: INestApplication) {
  const file = fs.readFileSync('src/docs/swagger.yaml', 'utf8');
  const swaggerDocument = yaml.parse(file);
  SwaggerModule.setup('api-docs', app, swaggerDocument);
}
// ---> http://localhost:3000/api-docs