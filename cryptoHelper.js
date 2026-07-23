import crypto from 'crypto';

const ALGORITHM = 'aes-256-cbc';

const getEncryptionKey = () => {
  // Use a hash of the ENCRYPTION_KEY env var (or a default fallback) to guarantee 32 bytes
  const key = (process.env.ENCRYPTION_KEY || 'panasonic-ac-default-secret-key-32bytes!').replace(/['"]/g, '');
  return crypto.createHash('sha256').update(key).digest();
};

export function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
}

export function decrypt(encryptedData, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
