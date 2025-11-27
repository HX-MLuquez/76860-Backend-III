import { Module } from '@nestjs/common';
import { StudentsService } from './students.service';
import { StudentsController } from './students.controller';

@Module({
  imports: [],
  controllers: [StudentsController],
  providers: [StudentsService],
})
export class StudentsModule {}
