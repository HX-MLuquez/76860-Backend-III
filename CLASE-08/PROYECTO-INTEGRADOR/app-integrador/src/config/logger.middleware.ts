import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { winstonLogger } from '../config/winston.config';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    res.on('finish', () => {
      winstonLogger.info({
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        timestamp: new Date().toISOString(),
      });
    });
    next();
  }
}