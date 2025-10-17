import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';

const SALT_ROUNDS = 12;

/**
 * Hash a password using bcrypt
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Verify password against hash using constant-time comparison
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    // If hash is invalid, still return false (constant time)
    return false;
  }
}

/**
 * Generate a cryptographically secure random token ID
 */
export function generateTokenId(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Generate a token family ID for refresh token rotation
 */
export function generateTokenFamily(): string {
  return randomBytes(16).toString('base64url');
}