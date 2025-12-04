import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
  @Prop({ required: true })
  username: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop()
  age?: number;

  @Prop({ enum: ['admin', 'user'], default: 'user' })
  role: 'admin' | 'user';
}

export const UserSchema = SchemaFactory.createForClass(User);
