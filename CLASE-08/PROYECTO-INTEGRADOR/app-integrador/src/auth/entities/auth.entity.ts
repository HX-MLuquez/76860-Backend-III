export class Auth {
    id: string;
    username: string;
    email: string;
    password: string;
    role: string; // 'user' | 'admin'
    createdAt: Date;
    updatedAt: Date;
    
    constructor(partial: Partial<Auth>) {
        Object.assign(this, partial);
    }
}
