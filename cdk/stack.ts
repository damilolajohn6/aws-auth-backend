import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as path from 'path';

export class AuthServiceStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const table = new dynamodb.Table(this, 'AuthTable', {
      tableName: 'auth-service-table',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: 'ttl', 
    });

    table.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'tokenFamily', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const jwtSecret = new secretsmanager.Secret(this, 'JWTSecret', {
      secretName: 'auth-service/jwt-secret',
      description: 'JWT signing secret for auth service',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: 'secret',
        excludePunctuation: true,
        passwordLength: 64,
      },
    });

    const lambdaConfig = {
      runtime: lambda.Runtime.NODEJS_20_X,
      memorySize: 512, 
      timeout: cdk.Duration.seconds(10),
      environment: {
        TABLE_NAME: table.tableName,
        JWT_SECRET_NAME: jwtSecret.secretName,
        NODE_OPTIONS: '--enable-source-maps',
      },
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'es2022',
        externalModules: [
          '@aws-sdk/client-dynamodb',
          '@aws-sdk/lib-dynamodb',
          '@aws-sdk/client-secrets-manager',
        ],
      },
      logRetention: logs.RetentionDays.ONE_WEEK,
    };

    // Register Lambda
    const registerFn = new NodejsFunction(this, 'RegisterFunction', {
      ...lambdaConfig,
      entry: path.join(__dirname, '../src/handlers/auth.ts'),
      handler: 'register',
      functionName: 'auth-service-register',
      description: 'User registration handler',
    });

    // Login Lambda
    const loginFn = new NodejsFunction(this, 'LoginFunction', {
      ...lambdaConfig,
      entry: path.join(__dirname, '../src/handlers/auth.ts'),
      handler: 'login',
      functionName: 'auth-service-login',
      description: 'User login handler',
    });

    // Refresh Token Lambda
    const refreshFn = new NodejsFunction(this, 'RefreshFunction', {
      ...lambdaConfig,
      entry: path.join(__dirname, '../src/handlers/auth.ts'),
      handler: 'refresh',
      functionName: 'auth-service-refresh',
      description: 'Token refresh handler',
    });

    // Grant permissions
    table.grantReadWriteData(registerFn);
    table.grantReadWriteData(loginFn);
    table.grantReadWriteData(refreshFn);

    jwtSecret.grantRead(registerFn);
    jwtSecret.grantRead(loginFn);
    jwtSecret.grantRead(refreshFn);

    // API Gateway with throttling
    const api = new apigateway.RestApi(this, 'AuthApi', {
      restApiName: 'Auth Service API',
      description: 'Secure authentication API',
      deployOptions: {
        stageName: 'prod',
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: false, 
        metricsEnabled: true,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS, 
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization'],
        maxAge: cdk.Duration.hours(1),
      },
    });

    const plan = api.addUsagePlan('UsagePlan', {
      name: 'Standard',
      throttle: {
        rateLimit: 50,
        burstLimit: 100,
      },
      quota: {
        limit: 10000,
        period: apigateway.Period.DAY,
      },
    });

    plan.addApiStage({
      stage: api.deploymentStage,
    });

    const authResource = api.root.addResource('auth');

    const registerResource = authResource.addResource('register');
    registerResource.addMethod('POST', new apigateway.LambdaIntegration(registerFn), {
      requestValidatorOptions: {
        validateRequestBody: true,
      },
    });

    const loginResource = authResource.addResource('login');
    loginResource.addMethod('POST', new apigateway.LambdaIntegration(loginFn), {
      requestValidatorOptions: {
        validateRequestBody: true,
      },
    });

    const tokenResource = authResource.addResource('token');
    const refreshResource = tokenResource.addResource('refresh');
    refreshResource.addMethod('POST', new apigateway.LambdaIntegration(refreshFn), {
      requestValidatorOptions: {
        validateRequestBody: true,
      },
    });

    const dashboard = new cdk.aws_cloudwatch.Dashboard(this, 'AuthDashboard', {
      dashboardName: 'auth-service-dashboard',
    });

    [registerFn, loginFn, refreshFn].forEach((fn) => {
      dashboard.addWidgets(
        new cdk.aws_cloudwatch.GraphWidget({
          title: `${fn.functionName} - Invocations & Errors`,
          left: [fn.metricInvocations(), fn.metricErrors()],
        }),
        new cdk.aws_cloudwatch.GraphWidget({
          title: `${fn.functionName} - Duration`,
          left: [fn.metricDuration()],
        })
      );
    });

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: api.url,
      description: 'Auth API Gateway URL',
    });

    new cdk.CfnOutput(this, 'TableName', {
      value: table.tableName,
      description: 'DynamoDB table name',
    });

    new cdk.CfnOutput(this, 'JWTSecretArn', {
      value: jwtSecret.secretArn,
      description: 'JWT secret ARN in Secrets Manager',
    });
  }
}
