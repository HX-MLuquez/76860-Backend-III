import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';

import { LoggerMiddleware } from './config/logger.middleware';

import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigService } from '@nestjs/config';
import configuration from './config/configuration';

import { CurrentUserMiddleware } from './common/middleware/current-user.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [configuration] }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService], // Inyecta ConfigService para acceder a las variables de entorno
      // ... y permite la configuración asíncrona de Mongoose
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGO_URI'),
      }),
    }),
    UsersModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*');
    consumer.apply(CurrentUserMiddleware).forRoutes('*'); // Aplica a todas las rutas
  }
}
