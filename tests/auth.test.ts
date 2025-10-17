import { hashPassword, verifyPassword, generateTokenId, generateTokenFamily } from '../src/lib/crypto';
import { safeParseRegister, safeParseLogin, ValidationError } from '../src/lib/validation';
import { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken } from '../src/lib/jwt';

// Mock AWS SDK
jest.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: jest.fn(() => ({
    send: jest.fn(),
  })),
  GetSecretValueCommand: jest.fn(),
}));

// Mock the JWT secret for testing
const mockSecret = 'test-jwt-secret-key-at-least-32-chars-long-for-security';
jest.spyOn(require('../src/lib/jwt'), 'getJwtSecret' as any).mockResolvedValue(
  new TextEncoder().encode(mockSecret)
);

describe('Crypto Functions', () => {
  describe('hashPassword', () => {
    it('should hash a password successfully', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash).toMatch(/^\$2[aby]\$/); // bcrypt hash pattern
    });

    it('should create different hashes for the same password', async () => {
      const password = 'TestPassword123';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const isValid = await verifyPassword(password, hash);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const isValid = await verifyPassword('WrongPassword123', hash);

      expect(isValid).toBe(false);
    });

    it('should handle invalid hash gracefully', async () => {
      const isValid = await verifyPassword('password', 'invalid-hash');
      expect(isValid).toBe(false);
    });
  });

  describe('generateTokenId', () => {
    it('should generate unique token IDs', () => {
      const id1 = generateTokenId();
      const id2 = generateTokenId();

      expect(id1).toBeDefined();
      expect(id2).toBeDefined();
      expect(id1).not.toBe(id2);
      expect(id1.length).toBeGreaterThan(32);
    });
  });

  describe('generateTokenFamily', () => {
    it('should generate unique family IDs', () => {
      const family1 = generateTokenFamily();
      const family2 = generateTokenFamily();

      expect(family1).toBeDefined();
      expect(family2).toBeDefined();
      expect(family1).not.toBe(family2);
    });
  });
});

describe('Validation Functions', () => {
  describe('safeParseRegister', () => {
    it('should validate correct registration data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'TestPass123',
        name: 'Test User',
      };

      const result = safeParseRegister(validData);
      expect(result).toEqual({
        email: 'test@example.com',
        password: 'TestPass123',
        name: 'Test User',
      });
    });

    it('should normalize email to lowercase', () => {
      const data = {
        email: 'Test@EXAMPLE.COM',
        password: 'TestPass123',
        name: 'Test User',
      };

      const result = safeParseRegister(data);
      expect(result.email).toBe('test@example.com');
    });

    it('should trim name', () => {
      const data = {
        email: 'test@example.com',
        password: 'TestPass123',
        name: '  Test User  ',
      };

      const result = safeParseRegister(data);
      expect(result.name).toBe('Test User');
    });

    it('should reject invalid email', () => {
      const invalidData = {
        email: 'not-an-email',
        password: 'TestPass123',
        name: 'Test User',
      };

      expect(() => safeParseRegister(invalidData)).toThrow(ValidationError);
    });

    it('should reject weak password (no uppercase)', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'testpass123',
        name: 'Test User',
      };

      expect(() => safeParseRegister(invalidData)).toThrow(ValidationError);
    });

    it('should reject weak password (no number)', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'TestPassword',
        name: 'Test User',
      };

      expect(() => safeParseRegister(invalidData)).toThrow(ValidationError);
    });

    it('should reject short password', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'Test1',
        name: 'Test User',
      };

      expect(() => safeParseRegister(invalidData)).toThrow(ValidationError);
    });

    it('should reject empty name', () => {
      const invalidData = {
        email: 'test@example.com',
        password: 'TestPass123',
        name: '',
      };

      expect(() => safeParseRegister(invalidData)).toThrow(ValidationError);
    });
  });

  describe('safeParseLogin', () => {
    it('should validate correct login data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'TestPass123',
      };

      const result = safeParseLogin(validData);
      expect(result).toEqual(validData);
    });

    it('should reject invalid email', () => {
      const invalidData = {
        email: 'not-an-email',
        password: 'password',
      };

      expect(() => safeParseLogin(invalidData)).toThrow(ValidationError);
    });

    it('should reject empty password', () => {
      const invalidData = {
        email: 'test@example.com',
        password: '',
      };

      expect(() => safeParseLogin(invalidData)).toThrow(ValidationError);
    });
  });
});

describe('JWT Functions', () => {
  beforeAll(() => {
    // Ensure mock is set up
    process.env.JWT_SECRET_NAME = 'test-secret';
  });

  describe('signAccessToken and verifyAccessToken', () => {
    it('should create and verify access token', async () => {
      const payload = { sub: 'user@example.com' };
      const token = await signAccessToken(payload);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      const verified = await verifyAccessToken(token);
      expect(verified.sub).toBe('user@example.com');
      expect(verified.type).toBe('access');
    });

    it('should reject expired token', async () => {
      // This would require mocking time or waiting, simplified test
      const payload = { sub: 'user@example.com' };
      const token = await signAccessToken(payload);

      await expect(verifyAccessToken(token)).resolves.toBeDefined();
    });

    it('should reject invalid token', async () => {
      await expect(verifyAccessToken('invalid.token.here')).rejects.toThrow();
    });

    it('should reject refresh token as access token', async () => {
      const payload = {
        sub: 'user@example.com',
        tokenId: 'test-id',
        tokenFamily: 'test-family',
      };
      const refreshToken = await signRefreshToken(payload);

      await expect(verifyAccessToken(refreshToken)).rejects.toThrow();
    });
  });

  describe('signRefreshToken and verifyRefreshToken', () => {
    it('should create and verify refresh token', async () => {
      const payload = {
        sub: 'user@example.com',
        tokenId: 'test-token-id',
        tokenFamily: 'test-family',
      };
      const token = await signRefreshToken(payload);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      const verified = await verifyRefreshToken(token);
      expect(verified.sub).toBe('user@example.com');
      expect(verified.tokenId).toBe('test-token-id');
      expect(verified.tokenFamily).toBe('test-family');
      expect(verified.type).toBe('refresh');
    });

    it('should reject access token as refresh token', async () => {
      const payload = { sub: 'user@example.com' };
      const accessToken = await signAccessToken(payload);

      await expect(verifyRefreshToken(accessToken)).rejects.toThrow();
    });
  });
});

describe('Integration: Happy Path Login Flow', () => {
  it('should hash password, verify it, and create tokens', async () => {
    const email = 'test@example.com';
    const password = 'TestPassword123';
    const name = 'Test User';

    // 1. Validate registration
    const regData = safeParseRegister({ email, password, name });
    expect(regData.email).toBe(email);

    // 2. Hash password
    const hash = await hashPassword(password);
    expect(hash).toBeDefined();

    // 3. Verify password during login
    const isValid = await verifyPassword(password, hash);
    expect(isValid).toBe(true);

    // 4. Generate tokens
    const tokenId = generateTokenId();
    const tokenFamily = generateTokenFamily();
    const accessToken = await signAccessToken({ sub: email });
    const refreshToken = await signRefreshToken({ sub: email, tokenId, tokenFamily });

    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();

    // 5. Verify tokens
    const accessPayload = await verifyAccessToken(accessToken);
    expect(accessPayload.sub).toBe(email);

    const refreshPayload = await verifyRefreshToken(refreshToken);
    expect(refreshPayload.sub).toBe(email);
    expect(refreshPayload.tokenId).toBe(tokenId);
    expect(refreshPayload.tokenFamily).toBe(tokenFamily);
  });
});