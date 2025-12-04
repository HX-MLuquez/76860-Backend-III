import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { CreateAuthDto } from './dto/create-auth.dto';
import { access } from 'fs';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: CreateAuthDto) {
    const userExists = await this.usersService.findByEmail(dto.email);
    if (userExists) {
      throw new UnauthorizedException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const newUser = await this.usersService.create({
      ...dto,
      password: hashedPassword,
    });

    const { password, ...result } = newUser.toObject();
    return { user: result, access_token: this.jwtService.sign({ sub: newUser._id, username: newUser.username, role: newUser.role }) };
  }

  async login(dto: CreateAuthDto) {
    const user = await this.usersService.findByEmail(dto.email);

    if (!user || !(await bcrypt.compare(dto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = {
      sub: user._id,
      username: user.username,
      role: user.role,
    };

    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      const { password, ...rest } = user.toObject();
      return rest;
    }
    return null;
  }

  async logout() {
    // Opcional: registrar token en blacklist 
    return { message: 'Logout successful. Please clear token on client.' };
  }
}
