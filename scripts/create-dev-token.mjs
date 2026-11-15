import { createHmac } from 'node:crypto';

const signingKey = process.env.JWT_SIGNING_KEY;
if (!signingKey || Buffer.byteLength(signingKey, 'utf8') < 32) {
  console.error('Impostare JWT_SIGNING_KEY (>= 32 byte). Es.: node --env-file=docker/.env scripts/create-dev-token.mjs');
  process.exit(1);
}

const organization = process.argv[2] ?? '11111111-1111-1111-1111-111111111111';
const role = process.argv[3] ?? 'Officer';
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(organization) ||
    !['Admin', 'Officer', 'Reader'].includes(role)) {
  console.error('Uso: node scripts/create-dev-token.mjs <organization-guid> [Admin|Officer|Reader]');
  process.exit(1);
}

const now = Math.floor(Date.now() / 1000);
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const data = [
  encode({ alg: 'HS256', typ: 'JWT' }),
  encode({
    iss: process.env.JWT_ISSUER ?? 'Comuni.Development',
    aud: process.env.JWT_AUDIENCE ?? 'Comuni.Api',
    sub: 'local-developer', organization_id: organization,
    role, iat: now, exp: now + 3600
  })
].join('.');
const signature = createHmac('sha256', signingKey).update(data).digest('base64url');
console.log(`${data}.${signature}`);
