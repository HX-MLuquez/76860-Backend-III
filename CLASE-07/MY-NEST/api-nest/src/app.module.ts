import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ProductsModule } from './modules/products/products.module';
import { PaymentsModule } from './modules/payments/payments.module';
import { CartsModule } from './modules/carts/carts.module';
import { OrdersModule } from './modules/orders/orders.module';
import { UsersModule } from './modules/users/users.module';

//* Importación para conectar a nuestra base de datos Mongo DG con la ODM Mongoose
import { MongooseModule } from '@nestjs/mongoose';

//* Importaciones para nuestro CONFIG - .ENV
import { ConfigModule, ConfigService } from '@nestjs/config';
import configuration from './config/configuration';

//* Importaciones para inyectar nuestros middlewares en nuestras routes
import { MiddlewareConsumer, NestModule, RequestMethod } from '@nestjs/common';
import { LoggerMiddleware } from './middleware/logger.middleware';

@Module({
  imports: [
    //* Configuración para conectar a nuestra base de datos Mongo DG con la ODM Mongoose sin variables de entorno
    // MongooseModule.forRoot('mongodb://localhost/nestjs-api'),
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('mongoUri'),
      }),
    }),
    ProductsModule,
    PaymentsModule,
    CartsModule,
    OrdersModule,
    UsersModule,
  ],

  controllers: [AppController], // -> (req, res)->
  providers: [AppService], // -> Lógica de negocio
})

//* Configuración para aplicar nuestros middlewares a nuestras routes
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}

// export class AppModule {}
