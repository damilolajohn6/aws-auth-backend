import * as jose from 'jose';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { AccessTokenPayload, RefreshTokenPayload } from '../types/dto';

const client = new SecretsManagerClient({});
const SECRET_NAME = process.env.JWT_SECRET_NAME || 'auth-service/jwt-secret';

// Cache the secret to avoid repeated API calls
let cachedSecret: Uint8Array | null = null;

/**
 * Fetches the JWT secret from Secrets Manager and caches it to avoid repeated API calls.
 */
export async function getJwtSecret(): Promise<Uint8Array> {
  // If a direct JWT secret is provided, prefer it (local development)
  if (process.env.JWT_SECRET) {
    if (!cachedSecret) {
      cachedSecret = new TextEncoder().encode(process.env.JWT_SECRET);
    }
    return cachedSecret;
  }

  // In test environment, use an env-provided secret or a deterministic fallback
  if (process.env.NODE_ENV === 'test') {
    if (!cachedSecret) {
      const raw = process.env.JWT_SECRET || 'test-jwt-secret-key-at-least-32-chars-long-for-security';
      cachedSecret = new TextEncoder().encode(raw);
    }
    return cachedSecret;
  }

  if (cachedSecret) {
    return cachedSecret;
  }

  try {
    const response = await client.send(
      new GetSecretValueCommand({ SecretId: SECRET_NAME })
    );
    
    if (!response.SecretString) {
      throw new Error('JWT secret not found in Secrets Manager');
    }

    let secretString = response.SecretString;
    try {
      const parsed = JSON.parse(secretString);
      if (parsed && typeof parsed.secret === 'string') {
        secretString = parsed.secret;
      }
    } catch {
      // not JSON, treat as raw secret string
    }

    cachedSecret = new TextEncoder().encode(secretString);
    return cachedSecret;
  } catch (error) {
    console.error('Failed to fetch JWT secret:', error);
    throw new Error('Unable to retrieve JWT secret');
  }
}

const ACCESS_TOKEN_TTL = 15 * 60; // 15 minutes in seconds
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60; // 7 days in seconds

/**
 * Sign an access token with 15-minute expiry
 */
export async function signAccessToken(payload: Omit<AccessTokenPayload, 'type' | 'iat' | 'exp'>): Promise<string> {
  const secret = await getJwtSecret();
  
  return await new jose.SignJWT({ ...payload, type: 'access' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(secret);
}

/**
 * Sign a refresh token with 7-day expiry
 */
export async function signRefreshToken(
  payload: Omit<RefreshTokenPayload, 'type' | 'iat' | 'exp'>
): Promise<string> {
  const secret = await getJwtSecret();
  
  return await new jose.SignJWT({ ...payload, type: 'refresh' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secret);
}

/**
 * Verify and decode an access token
 */
export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
  const secret = await getJwtSecret();
  
  try {
    const { payload } = await jose.jwtVerify(token, secret, {
      algorithms: ['HS256'],
    });

    if (payload.type !== 'access') {
      throw new Error('Invalid token type');
    }

    return payload as unknown as AccessTokenPayload;
  } catch (error) {
    throw new Error('Invalid or expired access token');
  }
}

/**
 * Verify and decode a refresh token
 */
export async function verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
  const secret = await getJwtSecret();
  
  try {
    const { payload } = await jose.jwtVerify(token, secret, {
      algorithms: ['HS256'],
    });

    if (payload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    return payload as unknown as RefreshTokenPayload;
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
}

export { ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL };