import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { Render, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { join } from 'path';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('/')
  @Render('home')
  home(@Res() res: Response) {
    return {
      title: 'Inicio',
      user: res.locals.user || null,
    };
  }
  @Get('test-css')
  testCss(@Res() res: Response) {
    const cssPath = join(__dirname, '..', 'public', 'styles', 'main.css');
    return res.sendFile(cssPath);
  }
}
