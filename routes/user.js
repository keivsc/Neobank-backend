import express from 'express';
import dotenv from 'dotenv';
import Logger from '../src/logging.js';
import { createAccount, deleteAccount, getUsernameById, login, verifyTotp } from '../services/user.js';
import { generateToken, getToken, verifyToken } from '../services/session.js';
import { verifyChallengeAndIssueToken } from '../services/user.js';

dotenv.config({ quiet: true });
const router = express.Router();
const logger = new Logger('user');

router.use((req, res, next) => {
    const deviceId = req.cookies['x-device-id'];
    if (!deviceId) return res.status(400).json({ error: "Missing device id." });
    next();
});

router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: "Missing username, email or password." });
        const { userId, otpauthURL } = await createAccount({ username, email, password });
        logger.log(`New user registered: ${email}`);
        res.status(200).json({ success: true, otpauthURL });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password, signPublic, encryptPublic } = req.body;
        const deviceId = req.cookies['x-device-id'];
        const result = await login({ email, password, deviceId, signPublic, encryptPublic });
        res.status(200).json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/totp', async (req, res) => {
    try {
        const { totp, userId } = req.body;
        const deviceId = req.cookies['x-device-id'];
        const valid = await verifyTotp({ deviceId, userId, token: totp });
        if (!valid) return res.status(400).json({ error: "Invalid TOTP code." });

        const sessionToken = await generateToken(userId, deviceId);
        res.cookie('session', sessionToken, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 3600 * 1000 });
        res.status(200).json({ success: true });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.get('/name', async(req, res)=>{
    const token = req.cookies['session'];
    const deviceId = req.cookies['x-device-id'];
    if (!deviceId || !token){
        return res.status(400).json({error:"Missing device id."});
    }
    const userID = await verifyToken(token, deviceId);
    if(!userID){
        return res.status(400).json({error:"Invalid Session"});
    }
    const username = await getUsernameById(userID);
    return res.status(200).json({username});
})



router.post('/verify', async (req, res) => {
    try {
        const { signature, nonce } = req.body;
        const deviceId = req.cookies['x-device-id'];

        const result = await verifyChallengeAndIssueToken({
            deviceId,
            signature,
            nonce,
            ip: req.ip
        });

        if (result.totpRequired) {
            return res.status(401).json({
                error: "TOTP required.",
                userId: result.userId,
                expiresAt: result.expiresAt
            });
        }

        res.cookie('session', result.sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 60 * 60 * 1000
        });

        return res.status(200).json({ success: true });

    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
});

router.post('/session', async (req, res) => {
    const token = req.cookies['session'];
    const deviceId = req.cookies['x-device-id'];

    if (!deviceId || !token) {
        return res.status(400).json({ error: "Missing device id." });
    }

    const userId = verifyToken(token, deviceId);
    if (!userId) {
        return res.status(400).json({ error: "Invalid Session" });
    }

    return res.status(200).json({ success: true });
});


export default router;