export class User {
    id: string;
    username: string;
    email: string;
    password: string;
    role: 'user' | 'admin';
    createdAt: Date;
    updatedAt: Date;

    constructor(partial: Partial<User>) {
        Object.assign(this, partial);
    }
}
