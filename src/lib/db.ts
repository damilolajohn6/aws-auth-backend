import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { UserProfile, RefreshTokenRecord } from '../types/dto';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client, {
  marshallOptions: {
    removeUndefinedValues: true,
  },
});

const TABLE_NAME = process.env.TABLE_NAME || 'auth-service-table';
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

/**
 * Get user by email
 */
export async function getUserByEmail(email: string): Promise<UserProfile | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `USER#${email}`,
        sk: 'PROFILE',
      },
    })
  );

  return result.Item as UserProfile | null;
}

/**
 * Create a new user (idempotent with conditional expression)
 */
export async function putUser(data: {
  email: string;
  name: string;
  password_hash: string;
}): Promise<void> {
  const now = new Date().toISOString();
  const user: UserProfile = {
    pk: `USER#${data.email}`,
    sk: 'PROFILE',
    email: data.email,
    name: data.name,
    password_hash: data.password_hash,
    createdAt: now,
    updatedAt: now,
    failedLoginCount: 0,
  };

  try {
    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: user,
        ConditionExpression: 'attribute_not_exists(pk)',
      })
    );
  } catch (error: any) {
    if (error.name === 'ConditionalCheckFailedException') {
      throw new Error('User already exists');
    }
    throw error;
  }
}

/**
 * Update login metadata after successful login
 */
export async function updateLoginMeta(
  email: string,
  data: { lastLoginAt: string; failedLoginCount: number }
): Promise<void> {
  await docClient.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `USER#${email}`,
        sk: 'PROFILE',
      },
      UpdateExpression:
        'SET lastLoginAt = :lastLogin, failedLoginCount = :failCount, updatedAt = :now, accountLocked = :locked REMOVE accountLockedUntil',
      ExpressionAttributeValues: {
        ':lastLogin': data.lastLoginAt,
        ':failCount': data.failedLoginCount,
        ':now': new Date().toISOString(),
        ':locked': false,
      },
    })
  );
}

/**
 * Increment failed login count and lock account if threshold exceeded
 */
export async function incrementFailedLogin(email: string): Promise<{ locked: boolean }> {
  const user = await getUserByEmail(email);
  if (!user) {
    return { locked: false };
  }

  const newFailCount = (user.failedLoginCount || 0) + 1;
  const shouldLock = newFailCount >= MAX_FAILED_LOGINS;

  const updateExpr = shouldLock
    ? 'SET failedLoginCount = :count, accountLocked = :locked, accountLockedUntil = :until, updatedAt = :now'
    : 'SET failedLoginCount = :count, updatedAt = :now';

  const exprValues: Record<string, any> = {
    ':count': newFailCount,
    ':now': new Date().toISOString(),
  };

  if (shouldLock) {
    const lockUntil = new Date();
    lockUntil.setMinutes(lockUntil.getMinutes() + LOCKOUT_DURATION_MINUTES);
    exprValues[':locked'] = true;
    exprValues[':until'] = lockUntil.toISOString();
  }

  await docClient.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `USER#${email}`,
        sk: 'PROFILE',
      },
      UpdateExpression: updateExpr,
      ExpressionAttributeValues: exprValues,
    })
  );

  return { locked: shouldLock };
}

/**
 * Check if account is currently locked
 */
export function isAccountLocked(user: UserProfile): boolean {
  if (!user.accountLocked) {
    return false;
  }

  if (user.accountLockedUntil) {
    const lockUntil = new Date(user.accountLockedUntil);
    if (new Date() > lockUntil) {
      return false; // Lock expired
    }
  }

  return true;
}

/**
 * Store refresh token record
 */
export async function storeRefreshToken(token: RefreshTokenRecord): Promise<void> {
  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: token,
    })
  );
}

/**
 * Get refresh token record
 */
export async function getRefreshToken(tokenId: string): Promise<RefreshTokenRecord | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `TOKEN#${tokenId}`,
        sk: 'REFRESH',
      },
    })
  );

  return result.Item as RefreshTokenRecord | null;
}

/**
 * Revoke a refresh token
 */
export async function revokeRefreshToken(tokenId: string): Promise<void> {
  await docClient.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `TOKEN#${tokenId}`,
        sk: 'REFRESH',
      },
      UpdateExpression: 'SET isRevoked = :revoked',
      ExpressionAttributeValues: {
        ':revoked': true,
      },
    })
  );
}

/**
 * Revoke all tokens in a token family (for token rotation breach detection)
 */
export async function revokeTokenFamily(userId: string, tokenFamily: string): Promise<void> {
  // Query all tokens for this user and family using composite key on GSI1
  let lastEvaluatedKey: Record<string, any> | undefined = undefined;
  do {
    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        IndexName: 'GSI1', // GSI has partitionKey=userId, sortKey=tokenFamily
        KeyConditionExpression: 'userId = :userId AND tokenFamily = :family',
        ExpressionAttributeValues: {
          ':userId': userId,
          ':family': tokenFamily,
        },
        ExclusiveStartKey: lastEvaluatedKey,
      })
    );

    const revokePromises = (result.Items || []).map((item) =>
      revokeRefreshToken((item as any).pk.replace('TOKEN#', ''))
    );
    await Promise.all(revokePromises);

    lastEvaluatedKey = result.LastEvaluatedKey as any;
  } while (lastEvaluatedKey);
}