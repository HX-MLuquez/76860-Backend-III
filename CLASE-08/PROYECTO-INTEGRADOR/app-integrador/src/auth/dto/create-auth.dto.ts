import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';
export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}
export class CreateAuthDto {
  @IsOptional()
  @IsString()
  username: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsOptional()
  age?: number;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
