import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { StudentsModule } from './students/students.module';
import { CoursesModule } from './courses/courses.module';
import { ProfessorsModule } from './professors/professors.module';

@Module({
  imports: [StudentsModule, CoursesModule, ProfessorsModule],
  controllers: [AppController], // Manejamos CONTROLLERS + ROUTERS
  providers: [AppService], // Manejamos SERVICES + DAO
})
export class AppModule {}
