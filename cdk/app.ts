#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AuthServiceStack } from './stack';

const app = new cdk.App();

new AuthServiceStack(app, 'AuthServiceStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
  },
  description: 'Secure authentication service with user registration and login',
});

app.synth();