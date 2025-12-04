// exceptions/http-exception.filter.ts
import { 
  ExceptionFilter, 
  Catch, 
  ArgumentsHost, 
  HttpException, 
  HttpStatus 
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Error interno del servidor';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const errorResponse = exception.getResponse();
      message = typeof errorResponse === 'string' 
        ? errorResponse 
        : (errorResponse as any).message || message;
    }

    // Detectar si es una petición que espera HTML
    const acceptsHtml = request.headers.accept?.includes('text/html');
    
    if (acceptsHtml) {
      // Renderizar vista para peticiones HTML
      const errorData = {
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        message: status === HttpStatus.NOT_FOUND 
          ? `La ruta '${request.url}' no fue encontrada` 
          : message,
        error: this.getErrorName(status),
        userAgent: request.headers['user-agent'],
        method: request.method
      };

      if (status === HttpStatus.NOT_FOUND) {
        response.status(status).render('errors/404', errorData);
      } else {
        response.status(status).render('errors/error', errorData);
      }
    } else {
      // Respuesta JSON para APIs
      response.status(status).json({
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        message,
        error: this.getErrorName(status)
      });
    }
  }

  private getErrorName(status: number): string {
    switch (status) {
      case HttpStatus.NOT_FOUND:
        return 'Not Found';
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'Internal Server Error';
      case HttpStatus.BAD_REQUEST:
        return 'Bad Request';
      case HttpStatus.UNAUTHORIZED:
        return 'Unauthorized';
      case HttpStatus.FORBIDDEN:
        return 'Forbidden';
      default:
        return 'Error';
    }
  }
}