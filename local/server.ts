import http from 'http';
import { register, login, refresh } from '../src/handlers/auth';
import { APIGatewayProxyEventV2 } from 'aws-lambda';

const PORT = parseInt(process.env.PORT || '4000', 10);

function send(res: http.ServerResponse, statusCode: number, body: string, headers?: Record<string, string>) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    ...(headers || {}),
  });
  res.end(body);
}

function toEvent(body: any): APIGatewayProxyEventV2 {
  return {
    version: '2.0',
    routeKey: '',
    rawPath: '',
    rawQueryString: '',
    headers: {},
    requestContext: {} as any,
    isBase64Encoded: false,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    queryStringParameters: undefined,
    pathParameters: undefined,
    stageVariables: undefined,
    cookies: undefined,
    multiValueHeaders: undefined as any,
  } as APIGatewayProxyEventV2;
}

type LambdaHandler = (
  event: APIGatewayProxyEventV2,
  context?: any,
  callback?: any
) => Promise<any> | any;

const server = http.createServer(async (req, res) => {
  if (!req.url) return send(res, 404, JSON.stringify({ message: 'Not found' }));

  // Preflight
  if (req.method === 'OPTIONS') {
    return send(res, 200, '');
  }

  const chunks: Uint8Array[] = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    const method = req.method || 'GET';
    const url = req.url || '';

    try {
      let handler: LambdaHandler | undefined;
      if (method === 'POST' && url === '/auth/register') handler = register;
      else if (method === 'POST' && url === '/auth/login') handler = login;
      else if (method === 'POST' && url === '/auth/token/refresh') handler = refresh;

      if (!handler) {
        return send(res, 404, JSON.stringify({ message: 'Not found' }));
      }

      const event = toEvent(raw || '{}');
      const result = await handler(event, {} as any, (() => {}) as any);
      const statusCode = (result as any).statusCode || 200;
      const body = (result as any).body || '';
      const headers = (result as any).headers || {};
      return send(res, statusCode, body, headers as any);
    } catch (err: any) {
      return send(res, 500, JSON.stringify({ message: 'Internal server error' }));
    }
  });
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Local auth server listening on http://localhost:${PORT}`);
  // eslint-disable-next-line no-console
  console.log('Endpoints: POST /auth/register, POST /auth/login, POST /auth/token/refresh');
});
