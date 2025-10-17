import { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import {
  getUserByEmail,
  putUser,
  updateLoginMeta,
  incrementFailedLogin,
  isAccountLocked,
  storeRefreshToken,
  getRefreshToken,
  revokeRefreshToken,
  revokeTokenFamily,
} from '../lib/db';
import { hashPassword, verifyPassword, generateTokenId, generateTokenFamily } from '../lib/crypto';
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  ACCESS_TOKEN_TTL,
  REFRESH_TOKEN_TTL,
} from '../lib/jwt';
import {
  safeParseRegister,
  safeParseLogin,
  safeParseRefreshToken,
  ValidationError,
} from '../lib/validation';
import { AuthResponse, ErrorResponse, RefreshTokenRecord } from '../types/dto';

/**
 * Create standardized response
 */
function createResponse(statusCode: number, body: AuthResponse | ErrorResponse) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    },
    body: JSON.stringify(body),
  };
}

/**
 * Log structured event (excludes sensitive data)
 */
function logEvent(event: string, details: Record<string, any>) {
  console.log(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      event,
      ...details,
    })
  );
}

/**
 * POST /register
 * Create new user account
 */
export const register: APIGatewayProxyHandlerV2 = async (event) => {
  const startTime = Date.now();

  try {
    const body = JSON.parse(event.body ?? '{}');
    const data = safeParseRegister(body);

    // Check if user exists
    const exists = await getUserByEmail(data.email);
    if (exists) {
      logEvent('registration_failed', {
        reason: 'user_exists',
        email: data.email,
        duration_ms: Date.now() - startTime,
      });
      return createResponse(409, { message: 'User already exists' });
    }

    // Hash password and create user
    const password_hash = await hashPassword(data.password);
    await putUser({
      email: data.email,
      name: data.name,
      password_hash,
    });

    logEvent('user_registered', {
      email: data.email,
      duration_ms: Date.now() - startTime,
    });

    return createResponse(201, {
      message: 'User registered successfully',
    } as ErrorResponse);
  } catch (error) {
    if (error instanceof ValidationError) {
      logEvent('registration_failed', {
        reason: 'validation_error',
        errors: error.errors,
        duration_ms: Date.now() - startTime,
      });
      return createResponse(400, {
        message: 'Invalid input',
        code: 'VALIDATION_ERROR',
      });
    }

    logEvent('registration_failed', {
      reason: 'internal_error',
      error: (error as Error).message,
      duration_ms: Date.now() - startTime,
    });

    return createResponse(500, {
      message: 'Registration failed',
      code: 'INTERNAL_ERROR',
    });
  }
};

/**
 * POST /login
 * Authenticate user and return tokens
 */
export const login: APIGatewayProxyHandlerV2 = async (event) => {
  const startTime = Date.now();
  const now = new Date().toISOString();

  try {
    const body = JSON.parse(event.body ?? '{}');
    const data = safeParseLogin(body);

    // Get user
    const user = await getUserByEmail(data.email);

    // Check if account is locked
    if (user && isAccountLocked(user)) {
      logEvent('login_failed', {
        reason: 'account_locked',
        email: data.email,
        duration_ms: Date.now() - startTime,
      });
      return createResponse(403, {
        message: 'Account is temporarily locked due to multiple failed login attempts',
        code: 'ACCOUNT_LOCKED',
      });
    }

    // Verify credentials (constant-time)
    const isValid = user && (await verifyPassword(data.password, user.password_hash));

    if (!isValid) {
      // Increment failed login count
      if (user) {
        const { locked } = await incrementFailedLogin(data.email);
        logEvent('login_failed', {
          reason: 'invalid_credentials',
          email: data.email,
          account_locked: locked,
          duration_ms: Date.now() - startTime,
        });
      } else {
        logEvent('login_failed', {
          reason: 'user_not_found',
          email: data.email,
          duration_ms: Date.now() - startTime,
        });
      }

      return createResponse(401, {
        message: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS',
      });
    }

    // Generate tokens
    const tokenId = generateTokenId();
    const tokenFamily = generateTokenFamily();

    const accessToken = await signAccessToken({ sub: user!.email });
    const refreshToken = await signRefreshToken({
      sub: user!.email,
      tokenId,
      tokenFamily,
    });

    // Store refresh token record
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + REFRESH_TOKEN_TTL);

    const tokenRecord: RefreshTokenRecord = {
      pk: `TOKEN#${tokenId}`,
      sk: 'REFRESH',
      userId: user!.email,
      tokenFamily,
      isRevoked: false,
      expiresAt: expiresAt.toISOString(),
      createdAt: now,
      ttl: Math.floor(expiresAt.getTime() / 1000),
    };

    await storeRefreshToken(tokenRecord);

    // Update login metadata
    await updateLoginMeta(user!.email, {
      lastLoginAt: now,
      failedLoginCount: 0,
    });

    logEvent('login_success', {
      email: user!.email,
      duration_ms: Date.now() - startTime,
    });

    return createResponse(200, {
      accessToken,
      refreshToken,
      expiresIn: ACCESS_TOKEN_TTL,
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      logEvent('login_failed', {
        reason: 'validation_error',
        errors: error.errors,
        duration_ms: Date.now() - startTime,
      });
      return createResponse(400, {
        message: 'Invalid input',
        code: 'VALIDATION_ERROR',
      });
    }

    logEvent('login_failed', {
      reason: 'internal_error',
      error: (error as Error).message,
      duration_ms: Date.now() - startTime,
    });

    return createResponse(500, {
      message: 'Login failed',
      code: 'INTERNAL_ERROR',
    });
  }
};

/**
 * POST /token/refresh
 * Rotate refresh token and issue new access token
 */
export const refresh: APIGatewayProxyHandlerV2 = async (event) => {
  const startTime = Date.now();
  const now = new Date().toISOString();

  try {
    const body = JSON.parse(event.body ?? '{}');
    const data = safeParseRefreshToken(body);

    // Verify and decode refresh token
    const payload = await verifyRefreshToken(data.refreshToken);

    // Get token record from database
    const tokenRecord = await getRefreshToken(payload.tokenId);

    if (!tokenRecord) {
      logEvent('token_refresh_failed', {
        reason: 'token_not_found',
        duration_ms: Date.now() - startTime,
      });
      return createResponse(401, {
        message: 'Invalid refresh token',
        code: 'INVALID_TOKEN',
      });
    }

    // Check if token is revoked
    if (tokenRecord.isRevoked) {
      // Token reuse detected - revoke entire token family
      await revokeTokenFamily(payload.sub, payload.tokenFamily);

      logEvent('token_refresh_failed', {
        reason: 'token_reuse_detected',
        userId: payload.sub,
        tokenFamily: payload.tokenFamily,
        duration_ms: Date.now() - startTime,
      });

      return createResponse(401, {
        message: 'Token reuse detected. All tokens in family revoked.',
        code: 'TOKEN_REUSE',
      });
    }

    // Check if token expired
    if (new Date(tokenRecord.expiresAt) < new Date()) {
      logEvent('token_refresh_failed', {
        reason: 'token_expired',
        userId: payload.sub,
        duration_ms: Date.now() - startTime,
      });
      return createResponse(401, {
        message: 'Refresh token expired',
        code: 'TOKEN_EXPIRED',
      });
    }

    // Revoke old token (rotation)
    await revokeRefreshToken(payload.tokenId);

    // Generate new tokens with same family
    const newTokenId = generateTokenId();
    const accessToken = await signAccessToken({ sub: payload.sub });
    const refreshToken = await signRefreshToken({
      sub: payload.sub,
      tokenId: newTokenId,
      tokenFamily: payload.tokenFamily, // Keep same family
    });

    // Store new refresh token record
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + REFRESH_TOKEN_TTL);

    const newTokenRecord: RefreshTokenRecord = {
      pk: `TOKEN#${newTokenId}`,
      sk: 'REFRESH',
      userId: payload.sub,
      tokenFamily: payload.tokenFamily,
      isRevoked: false,
      expiresAt: expiresAt.toISOString(),
      createdAt: now,
      lastUsedAt: now,
      ttl: Math.floor(expiresAt.getTime() / 1000),
    };

    await storeRefreshToken(newTokenRecord);

    logEvent('token_refresh_success', {
      userId: payload.sub,
      tokenFamily: payload.tokenFamily,
      duration_ms: Date.now() - startTime,
    });

    return createResponse(200, {
      accessToken,
      refreshToken,
      expiresIn: ACCESS_TOKEN_TTL,
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      logEvent('token_refresh_failed', {
        reason: 'validation_error',
        errors: error.errors,
        duration_ms: Date.now() - startTime,
      });
      return createResponse(400, {
        message: 'Invalid input',
        code: 'VALIDATION_ERROR',
      });
    }

    logEvent('token_refresh_failed', {
      reason: 'internal_error',
      error: (error as Error).message,
      duration_ms: Date.now() - startTime,
    });

    return createResponse(500, {
      message: 'Token refresh failed',
      code: 'INTERNAL_ERROR',
    });
  }
};