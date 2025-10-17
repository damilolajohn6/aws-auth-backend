import { ZodSchema, ZodError } from 'zod';
import { RegisterSchema, LoginSchema, RefreshTokenSchema } from '../types/dto';

export class ValidationError extends Error {
  constructor(public errors: string[]) {
    super('Validation failed');
    this.name = 'ValidationError';
  }
}

function parseWithSchema<T>(schema: ZodSchema<T>, data: unknown): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof ZodError) {
      const messages = error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
      throw new ValidationError(messages);
    }
    throw error;
  }
}

export function safeParseRegister(data: unknown) {
  return parseWithSchema(RegisterSchema, data);
}

export function safeParseLogin(data: unknown) {
  return parseWithSchema(LoginSchema, data);
}

export function safeParseRefreshToken(data: unknown) {
  return parseWithSchema(RefreshTokenSchema, data);
}
