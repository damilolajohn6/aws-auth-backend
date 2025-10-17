# AWS Auth Backend Service

A secure, scalable, and cost-effective user authentication service built with TypeScript on AWS Lambda, featuring user registration, login, and refresh token rotation.

## 🏗️ Architecture

- **Runtime**: Node.js 20.x with TypeScript 5+
- **API Gateway**: RESTful API with rate limiting and throttling
- **Lambda Functions**: Serverless compute for auth operations
- **DynamoDB**: Single-table design for user profiles and refresh tokens
- **Secrets Manager**: Secure JWT secret storage
- **CloudWatch**: Structured logging and metrics

## 🚀 Features

### Core Functionality
- ✅ User registration with email/password
- ✅ Secure login with JWT access tokens (15min TTL)
- ✅ Refresh token rotation with token family pattern
- ✅ Account lockout after 5 failed login attempts (15min lockout)
- ✅ Token reuse detection with automatic family revocation

### Security
- ✅ bcrypt password hashing (12 rounds)
- ✅ Constant-time password comparison
- ✅ JWT signing with Secrets Manager secret
- ✅ Input validation with Zod schemas
- ✅ Rate limiting and throttling via API Gateway
- ✅ PII minimization in logs
- ✅ Idempotent registration (conditional DynamoDB writes)

### Operational
- ✅ Structured JSON logging
- ✅ CloudWatch metrics and dashboard
- ✅ Cold start optimization (~500ms)
- ✅ Comprehensive unit tests with Jest

## 📋 Prerequisites

- Node.js 20.x or later
- AWS CLI configured with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)
- Git

## 🔧 Setup & Installation

### 1. Clone and Install Dependencies

```bash
git clone <repository-url>
cd aws-auth-backend
npm install
```

### 2. Build TypeScript

```bash
npm run build
```

### 3. Run Tests

```bash
npm test

# With coverage
npm run test:coverage
```

## 🚢 Deployment

### Deploy to AWS

```bash
# Bootstrap CDK (first time only)
cdk bootstrap

# Synthesize CloudFormation template
npm run synth

# Deploy the stack
npm run deploy
```

After deployment, note the API Gateway URL from the outputs:
```
Outputs:
AuthServiceStack.ApiUrl = https://xxxxxxxxxx.execute-api.us-east-1.amazonaws.com/prod/
```

### Destroy Stack

```bash
npm run destroy
```

## 🧪 Testing the API

### 1. Register a New User

```bash
curl -X POST https://YOUR_API_URL/prod/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123",
    "name": "John Doe"
  }'
```

**Response (201 Created):**
```json
{
  "message": "User registered successfully"
}
```

**Validation Rules:**
- Email: Valid email format, max 255 chars
- Password: Min 8 chars, must contain uppercase, lowercase, and number
- Name: 1-100 chars, trimmed

### 2. Login

```bash
curl -X POST https://YOUR_API_URL/prod/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123"
  }'
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

### 3. Refresh Token

```bash
curl -X POST https://YOUR_API_URL/prod/auth/token/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

## 🔐 Token Model & Validation

### Access Tokens
- **Type**: JWT (HS256)
- **TTL**: 15 minutes
- **Payload**: `{ sub: email, type: 'access', iat, exp }`
- **Use**: Authenticate API requests (future endpoints)

### Refresh Tokens
- **Type**: JWT (HS256)
- **TTL**: 7 days
- **Payload**: `{ sub: email, tokenId, tokenFamily, type: 'refresh', iat, exp }`
- **Use**: Obtain new access/refresh token pairs

### Token Family Pattern
The service implements the **Token Family** pattern for refresh token rotation:

1. On login, a new token family is created
2. Each refresh generates a new token within the same family
3. Old refresh token is immediately revoked
4. If a revoked token is reused, the entire family is revoked (breach detection)

**DynamoDB Token Record:**
```typescript
{
  pk: "TOKEN#<tokenId>",
  sk: "REFRESH",
  userId: "user@example.com",
  tokenFamily: "family-id",
  isRevoked: false,
  expiresAt: "2025-10-24T...",
  createdAt: "2025-10-17T...",
  lastUsedAt: "2025-10-17T..."
}
```

### Validation Strategy
- JWT signature verification using secret from Secrets Manager
- Token type validation (access vs refresh)
- Expiration validation
- Database lookup for refresh tokens (revocation check)
- Token reuse detection triggers family revocation

## 📊 Logs & Metrics

### Structured Logging
All events are logged in JSON format to CloudWatch:

```json
{
  "timestamp": "2025-10-17T12:34:56.789Z",
  "event": "login_success",
  "email": "user@example.com",
  "duration_ms": 234
}
```

**Event Types:**
- `user_registered`
- `login_success` / `login_failed`
- `token_refresh_success` / `token_refresh_failed`
- `registration_failed`

**Failure Reasons:**
- `user_exists`, `validation_error`, `invalid_credentials`
- `account_locked`, `token_reuse_detected`, `token_expired`
- `internal_error`

### CloudWatch Metrics
Automatically collected via CloudWatch:
- Lambda invocations, errors, duration
- API Gateway 4xx/5xx errors
- Request count and latency

**Dashboard**: Navigate to CloudWatch → Dashboards → `auth-service-dashboard`

### View Logs

```bash
# View logs for a specific function
aws logs tail /aws/lambda/auth-service-login --follow

# Filter for failed logins
aws logs filter-pattern /aws/lambda/auth-service-login --filter-pattern '"login_failed"'
```

## 🗄️ DynamoDB Schema

### Single-Table Design

**User Profile:**
```
pk: USER#user@example.com
sk: PROFILE
email: user@example.com
name: John Doe
password_hash: $2a$12$...
createdAt: 2025-10-17T...
updatedAt: 2025-10-17T...
lastLoginAt: 2025-10-17T...
failedLoginCount: 0
accountLocked: false
accountLockedUntil: (optional)
```

**Refresh Token:**
```
pk: TOKEN#abc123...
sk: REFRESH
userId: user@example.com
tokenFamily: family-xyz
isRevoked: false
expiresAt: 2025-10-24T...
createdAt: 2025-10-17T...
ttl: 1729814400 (epoch seconds for auto-cleanup)
```

**GSI1 (for token family queries):**
- Partition Key: `userId`
- Sort Key: `tokenFamily`
- Projection: ALL

### Access Patterns
1. **Get user by email**: `GetItem(pk=USER#email, sk=PROFILE)`
2. **Create user**: `PutItem` with `ConditionExpression: attribute_not_exists(pk)`
3. **Get refresh token**: `GetItem(pk=TOKEN#tokenId, sk=REFRESH)`
4. **Revoke token family**: `Query(GSI1, userId=email, FilterExpression: tokenFamily=X)`

## 🧪 Testing

### Run Unit Tests

```bash
npm test
```

### Test Coverage

```bash
npm run test:coverage
```

**Current Coverage:**
- Statements: 70%+
- Branches: 70%+
- Functions: 70%+
- Lines: 70%+

### Integration Testing

Use the provided curl commands or import this Postman collection:

```json
{
  "info": { "name": "Auth Service", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
  "item": [
    {
      "name": "Register",
      "request": {
        "method": "POST",
        "url": "{{baseUrl}}/auth/register",
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"TestPass123\",\n  \"name\": \"Test User\"\n}"
        }
      }
    }
  ]
}
```

## 📁 Project Structure

```
aws-auth-backend/
├── src/
│   ├── handlers/
│   │   └── auth.ts              # Lambda handlers (register, login, refresh)
│   ├── lib/
│   │   ├── crypto.ts            # Password hashing & token generation
│   │   ├── db.ts                # DynamoDB operations
│   │   ├── jwt.ts               # JWT signing & verification
│   │   └── validation.ts        # Zod schema validation
│   └── types/
│       └── dto.ts               # TypeScript types & Zod schemas
├── tests/
│   └── auth.test.ts             # Unit tests
├── cdk/
│   ├── app.ts                   # CDK app entry point
│   └── stack.ts                 # Infrastructure definition
├── package.json
├── tsconfig.json
├── jest.config.js
├── cdk.json
├── README.md
└── IMPROVEMENTS.md              # Performance, security, cost improvements
```

## 🔒 Security Considerations

1. **Password Storage**: bcrypt with 12 salt rounds
2. **Token Security**: JWT signed with 64-char secret from Secrets Manager
3. **Rate Limiting**: API Gateway throttling (50 req/s, burst 100)
4. **Account Lockout**: 5 failed attempts → 15min lockout
5. **Token Rotation**: Automatic refresh token rotation with breach detection
6. **Input Validation**: Zod schemas prevent injection attacks
7. **PII Protection**: Emails logged but passwords never logged

## 💰 Cost Optimization

- **DynamoDB**: On-demand billing mode (pay per request)
- **Lambda**: 512MB memory (balance cost vs cold start)
- **CloudWatch**: 7-day log retention
- **Secrets Manager**: Single secret, cached in memory
- **API Gateway**: REST API (cheaper than HTTP API for this use case)

**Estimated Monthly Cost** (1000 users, 10k requests/month):
- Lambda: ~$0.50
- DynamoDB: ~$2.50
- API Gateway: ~$3.50
- Secrets Manager: ~$0.40
- **Total: ~$7/month**

## 🚀 Next Steps

See [IMPROVEMENTS.md](./IMPROVEMENTS.md) for detailed recommendations on:
- Performance optimizations
- Advanced security features
- Cost reduction strategies
- Scalability improvements

## 📝 License

MIT

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## 📞 Support

For issues or questions, please open a GitHub issue.