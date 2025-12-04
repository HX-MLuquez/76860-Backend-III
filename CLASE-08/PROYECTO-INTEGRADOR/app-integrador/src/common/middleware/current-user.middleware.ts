import { Injectable, NestMiddleware } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response, NextFunction } from 'express';
import { UsersService } from '../../users/users.service';

@Injectable()
export class CurrentUserMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    private usersService: UsersService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const token = req.cookies?.jwt;

    if (token) {
      try {
        const payload = this.jwtService.verify(token);
        const user = await this.usersService.findById(payload.sub);
        if (user) {
          res.locals.user = user.toObject(); // pasa user a la vista
        }
      } catch (e) {
        // Token inválido, simplemente no hay usuario
      }
    }

    next();
  }
}
