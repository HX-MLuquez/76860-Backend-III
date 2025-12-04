import 'express-session';

declare module 'express-session' {
  interface SessionData {
    user?: {
      id: string;
      username: string;
      email: string;
      role: 'user' | 'admin';
      // password?: string; // Optional, not stored in session
    };
  }
}
