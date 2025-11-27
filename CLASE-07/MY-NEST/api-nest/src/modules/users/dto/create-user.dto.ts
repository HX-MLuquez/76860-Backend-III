export class CreateUserDto {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
  avatar: string;
}

export class UserList {
  id: string;
  first_name: string;
  avatar: string;
}

// Con estos moldes armados con clases DTOs y Entities, 
// podemos estandarizar la forma de los datos que vamos a recibir y manejar en nuestra aplicación.
// Y podemos avanzar a crear la lógica de negocio en el Service y los endpoints en el Controller.