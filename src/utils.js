
import crypto from 'crypto';


export function toPEM(base64Key) {
  // Decode from base64 back to binary
  const der = Buffer.from(base64Key, 'base64');

  // Convert to PEM
  const b64 = der.toString('base64');
  const pem =
    `-----BEGIN PUBLIC KEY-----\n` +
    b64.match(/.{1,64}/g).join('\n') +
    `\n-----END PUBLIC KEY-----`;

  return pem;
}

export function randomString(length = 6) {
    return crypto.randomBytes(length)
                 .toString('base64')
                 .replace(/[^a-zA-Z0-9]/g, '') 
                 .slice(0, length);
}

export function getFileType(filename) {
  const parts = filename.split('.');
  if (parts.length > 1) {
    return '.' + parts.pop();
  } else {
    return '.txt';
  }
}


export function fileToBlob(content) {
  const maxSize = 5 * 1024 * 1024; // 5 MB 

  let buffer;
  if (typeof content === 'string') {
    buffer = Buffer.from(content, 'utf-8');
  } else if (content instanceof Uint8Array) {
    buffer = Buffer.from(content);
  } else if (Buffer.isBuffer(content)) {
    buffer = content;
  } else {
    throw new Error('Unsupported file content type');
  }

  if (buffer.length > maxSize) {
    throw new Error('File exceeds 5 MB limit');
  }

  const blob = new Blob([buffer]);
  return blob;
}

export function hexToString(hex) {
  if (!hex) return '';
  const buffer = Buffer.from(hex, 'hex');
  return buffer.toString('utf-8');
}


const DEBUG_USER = 'admin';
const DEBUG_PASS = process.env.DEBUG_PASS;

export function requireDebugAuth(req, res, next) {
  // --- Basic Auth check ---
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Debug"');
    return res.status(401).send('Authentication required');
  }

  const [user, pass] = Buffer
    .from(auth.split(' ')[1], 'base64')
    .toString()
    .split(':');

  if (user !== DEBUG_USER || pass !== DEBUG_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Debug"');
    return res.status(401).send('Invalid credentials');
  }

  // --- IP check ---
  // Whitelist of allowed IPs
  const allowedIp = process.env.ALLOWED_IP
  const clientIp = (req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || 'unknown');

  if (allowedIp === clientIp) {
    return res.status(403).send(`Forbidden: IP ${clientIp} not allowed`);
  }

  next();
}
