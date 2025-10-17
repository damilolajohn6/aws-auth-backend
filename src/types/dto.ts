import { z } from 'zod';

// Request validation schemas
export const RegisterSchema = z.object({
  email: z.string().email().toLowerCase().max(255),
  password: z.string().min(8).max(128)
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  name: z.string().min(1).max(100).trim(),
});

export const LoginSchema = z.object({
  email: z.string().email().toLowerCase(),
  password: z.string().min(1),
});

export const RefreshTokenSchema = z.object({
  refreshToken: z.string().min(1),
});

// Infer types from schemas
export type RegisterInput = z.infer<typeof RegisterSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;
export type RefreshTokenInput = z.infer<typeof RefreshTokenSchema>;

// Database types
export interface UserProfile {
  pk: string; // USER#<email>
  sk: string; // PROFILE
  email: string;
  name: string;
  password_hash: string;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
  failedLoginCount: number;
  accountLocked?: boolean;
  accountLockedUntil?: string;
}

export interface RefreshTokenRecord {
  pk: string; // TOKEN#<tokenId>
  sk: string; // REFRESH
  userId: string; // email
  tokenFamily: string;
  isRevoked: boolean;
  expiresAt: string;
  createdAt: string;
  lastUsedAt?: string;
}

// JWT payload types
export interface AccessTokenPayload {
  sub: string; // user email
  type: 'access';
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  sub: string; // user email
  tokenId: string;
  tokenFamily: string;
  type: 'refresh';
  iat?: number;
  exp?: number;
}

// Response types
export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface ErrorResponse {
  message: string;
  code?: string;
}