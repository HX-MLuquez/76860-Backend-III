import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Request,
  Render,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Response } from 'express';

import { AuthGuard } from '@nestjs/passport';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login')
  @Render('auth/login')
  getLogin(@Req() req: Request) {
    return { title: 'Iniciar sesión' };
  }

  @Get('register')
  @Render('auth/register')
  getRegister(@Req() req: Request) {
    return { title: 'Registro' };
  }

  @Post('register')
  async register(
    @Body() dto: CreateAuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, access_token } = await this.authService.register(dto);
    res.cookie('jwt', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });
    return res.redirect('/');
    // return this.authService.register(dto);
  }

  @Post('login')
  async login(
    @Body() dto: CreateAuthDto,
    @Res({ passthrough: true }) res: Response, // Para setear cookies
  ) {
    const { access_token } = await this.authService.login(dto);

    res.cookie('jwt', access_token, {
      httpOnly: true, // Más seguro (no accesible por JS)
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 1 día
    });
    return res.redirect('/'); // Redirige al home
    // return this.authService.login(dto);
  }

  @Get('logout')
  @Render('home')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('jwt');
    return {
      message: 'Has cerrado sesión',
      user: null,
    };
  }

  @UseGuards() // No usamos AuthGuard - tenemos el usuario en res.locals
  @Get('profile')
  @Render('users/profile') 
  profile(@Res() res: Response) {
    const user = res.locals.user;

    if (!user) {
      return res.redirect('/auth/login'); 
    }
    return {
      title: 'Perfil',
      user,
    };
  }
}
