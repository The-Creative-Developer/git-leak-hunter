/** Minimal AWS Signature Version 4 signer (enough for one STS call; no SDK dependency). */
import { createHash, createHmac } from 'node:crypto';

const sha256 = (data: string): string => createHash('sha256').update(data, 'utf8').digest('hex');
const hmac = (key: Buffer | string, data: string): Buffer =>
  createHmac('sha256', key).update(data, 'utf8').digest();

export interface SignInput {
  method: string;
  host: string;
  path: string;
  /** Already-canonical query string (sorted, encoded), or ''. */
  query: string;
  /** Lower-case header names, excluding host and x-amz-date (added automatically). */
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** e.g. 20150830T123600Z */
  amzDate: string;
}

export function signingKey(secret: string, date: string, region: string, service: string): Buffer {
  return hmac(hmac(hmac(hmac(`AWS4${secret}`, date), region), service), 'aws4_request');
}

export function amzDateOf(d: Date): string {
  return d
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}/, '');
}

/** Returns the headers to send (incl. Authorization) and the signature, for testing. */
export function signRequest(i: SignInput): { headers: Record<string, string>; signature: string } {
  const all: Record<string, string> = { ...i.headers, host: i.host, 'x-amz-date': i.amzDate };
  const names = Object.keys(all)
    .map((n) => n.toLowerCase())
    .sort();
  const canonicalHeaders = names
    .map((n) => `${n}:${String(all[n]).trim().replace(/\s+/g, ' ')}\n`)
    .join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = [
    i.method,
    i.path,
    i.query,
    canonicalHeaders,
    signedHeaders,
    sha256(i.body),
  ].join('\n');
  const date = i.amzDate.slice(0, 8);
  const scope = `${date}/${i.region}/${i.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', i.amzDate, scope, sha256(canonicalRequest)].join('\n');
  const signature = createHmac('sha256', signingKey(i.secretAccessKey, date, i.region, i.service))
    .update(stringToSign, 'utf8')
    .digest('hex');
  const { host: _host, ...sendHeaders } = all;
  return {
    signature,
    headers: {
      ...sendHeaders,
      authorization: `AWS4-HMAC-SHA256 Credential=${i.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
  };
}
