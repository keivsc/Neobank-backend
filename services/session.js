import Database from '../src/db.js';
import Logger from '../src/logging.js';
import {randomBytes, createHmac} from 'crypto';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken'

dotenv.config({quiet:true});

const logger = new Logger('session');
const sesDb = new Database("session.db");

await sesDb.run(`CREATE TABLE IF NOT EXISTS sessions (
    userId TEXT PRIMARY KEY,
    deviceId TEXT,
    nonce TEXT,
    expiresAt INTEGER,
    trustScore INTEGER,
    token TEXT,
    IP TEXT
)`)




const HMAC_SECRET = Buffer.from(process.env.HMAC_SECRET, 'hex');
const JWT_SECRET = Buffer.from(process.env.JWT_SECRET, 'hex');

export async function generateToken(userId, deviceId, ip) {
  const nonce = randomBytes(16).toString('hex');

  // Payload object
  const payloadObj = { userId, deviceId, nonce };

  // Deterministic HMAC
  const hmac = createHmac('sha256', HMAC_SECRET)
                .update(JSON.stringify(payloadObj))
                .digest('hex');

  // JWT payload
  const jwtPayload = {
    payload: payloadObj,
    hmac
  };

  const sessionToken = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });
  const expiresAt = Date.now() + 1000 * 60 * 60;

  // Check if a session exists for this user
  const existingSession = await sesDb.get(
    `SELECT * FROM sessions WHERE userId = ?`,
    [userId]
  );

  if (existingSession) {
    // Delete old session
    await sesDb.run(
      `DELETE FROM sessions WHERE userId = ?`,
      [userId]
    );
  }

  // Insert new session
  await sesDb.run(
    `INSERT INTO sessions(userId, deviceId, nonce, expiresAt, trustScore, token, IP)
     VALUES(?, ?, ?, ?, ?, ?, ?)`,
    [userId, deviceId, nonce, expiresAt, 100, sessionToken, ip]
  );

  return sessionToken;
}



export async function getToken(userId, deviceId, deviceIp) {
    const session = await sesDb.get(
        `SELECT token, IP, trustScore FROM sessions WHERE userId = ? AND deviceId = ?`,
        [userId, deviceId]
    );

    if (!session || !session.token) {
        return null;
    }

    let trustScore = session.trustScore;

    if (session.IP !== deviceIp) {
        // Reduce trustScore if IP mismatch
        trustScore = Math.max(0, trustScore - 10); // reduce by 10
        await sesDb.run(
            `UPDATE sessions SET trustScore = ?, IP = ? WHERE userId = ? AND deviceId = ?`,
            [trustScore, deviceIp, userId, deviceId]
        );
    }

    // Reject if trustScore too low
    if (trustScore < 80) {
        await sesDb.run(
            `DELETE FROM sessions WHERE userId = ? AND deviceId = ?`,
            [userId, deviceId]
        )
        return null;
    }

    return session.token;
}



export async function verifyToken(token, deviceId){

    try {
        const tokenCheck = await sesDb.get(
            `SELECT deviceId, userId, nonce, trustScore FROM sessions WHERE token = ?`,
            [token]
        );
        if (!tokenCheck){
            throw new Error();
        }
        if (tokenCheck.trustScore < 80 || tokenCheck.deviceId !== deviceId){
            throw new Error();
        }
        const decoded = jwt.verify(token, JWT_SECRET);
        const expectedHmac = createHmac('sha256', HMAC_SECRET)
                                .update(JSON.stringify(decoded.payload))
                                .digest('hex');
        if (decoded.hmac !== expectedHmac) throw new Error();
        if (decoded.payload.userId !== tokenCheck.userId) throw new Error();
        return decoded.payload.userId;
    } catch (_) {
        await sesDb.run(`DELETE FROM sessions WHERE token = ?`, [token]);
        return null;
    }

}

export async function updateTrustScore(token, deviceId, score){

    const verified = await verifyToken(token, deviceId);
    if (!verified) return false;

    await sesDb.run(
        `UPDATE sessions
        SET trustScore = MIN(100, MAX(0, trustScore + ?))
        WHERE token = ?
        `,
        [score, token]
    );

    return true;

}

export async function getAll(){
    return await sesDb.getAll(`SELECT * FROM sessions`);
}