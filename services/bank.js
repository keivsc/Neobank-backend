import Database from "../src/db.js";
import { fileToBlob, getFileType, hexToString } from "../src/utils.js";
import {randomInt, randomUUID} from 'crypto';
import { getUsernameById } from "./user.js";
import { createHmac, randomBytes } from 'crypto';
import Logger from "../src/logging.js";

const logger = new Logger('bankDB')

const bankDb = new Database('bank.db');

await bankDb.run(`
  CREATE TABLE IF NOT EXISTS bankAccounts (
    accountNumber INTEGER PRIMARY KEY,
    type TEXT,
    balance INTEGER,
    userId TEXT
  )
`);

await bankDb.run(`
  CREATE TABLE IF NOT EXISTS moneyRequests (
    id TEXT PRIMARY KEY,
    fromUserId TEXT,
    toBankNumber INTEGER,
    amount INTEGER,
    expiry INTEGER,
    signature TEXT,
    status TEXT DEFAULT 'pending',  -- 'pending', 'completed', 'expired'
    createdAt INTEGER
  )
`);


// CREATE (only 1 account per user)
export async function createAccount(type, userId) {
  const accountNumber = generateAccountNumber();
  const existing = await bankDb.get(
    `SELECT 1 FROM bankAccounts WHERE userId = ?`,
    [userId]
  );

  if (existing) {
    return getAccount(userId);
  }

  await bankDb.run(
    `INSERT INTO bankAccounts (accountNumber, type, balance, userId)
     VALUES (?, ?, ?, ?)`,
    [accountNumber, type, 200000, userId]
  );

  return { success: true, account:getAccount(accountNumber) };
}

// ADD balance
export async function addBalance(userId, amount) {
  await bankDb.run(
    `UPDATE bankAccounts
     SET balance = balance + ?
     WHERE userId = ?`,
    [amount, userId]
  );

  return { success: true };
}

// DEDUCT balance
export async function deductBalance(userId, amount) {
  const acc = await bankDb.get(
    `SELECT balance FROM bankAccounts WHERE userId = ?`,
    [userId]
  );

  if (!acc) return { success: false, error: "Account not found." };
  if (acc.balance < amount)
    return { success: false, error: "Insufficient balance." };

  await bankDb.run(
    `UPDATE bankAccounts
     SET balance = balance - ?
     WHERE userId = ?`,
    [amount, userId]
  );

  return { success: true };
}

// DELETE account
export async function deleteAccount(userId) {
  const acc = await bankDb.get(
    `SELECT 1 FROM bankAccounts WHERE userId = ?`,
    [userId]
  );

  if (!acc) return { success: false, error: "Account not found." };

  await bankDb.run(
    `DELETE FROM bankAccounts WHERE userId = ?`,
    [userId]
  );

  return { success: true };
}
// TRANSFER balance from a userId to a target accountNumber
export async function transferBalance(fromUserId, toAccountNumber, amount) {
  if (amount <= 0 || amount > 999_999) {
    logger.warn(`Invalid transfer amount ${amount} from user ${fromUserId}`);
    return { success: false, error: "Invalid transfer amount. Max 999,999.00 allowed." };
  }


  // sender (by userId)
  const sender = await bankDb.get(
    `SELECT balance FROM bankAccounts WHERE userId = ?`,
    [fromUserId]
  );

  if (!sender) {
    return { success: false, error: "Sender account not found." };
  }

  if (sender.balance < amount) {
    return { success: false, error: "Insufficient balance." };
  }

  // receiver (by accountNumber)
  const receiver = await bankDb.get(
    `SELECT 1 FROM bankAccounts WHERE accountNumber = ?`,
    [toAccountNumber]
  );

  if (!receiver) {
    return { success: false, error: "Receiver account not found." };
  }

  try {
    // atomic transaction
    await bankDb.run("BEGIN TRANSACTION");

    await bankDb.run(
      `UPDATE bankAccounts
       SET balance = balance - ?
       WHERE userId = ?`,
      [amount, fromUserId]
    );

    await bankDb.run(
      `UPDATE bankAccounts
       SET balance = balance + ?
       WHERE accountNumber = ?`,
      [amount, toAccountNumber]
    );

    await bankDb.run("COMMIT");
    return { success: true };
    } catch (err) {
      logger.warn(`Transaction rollback triggered: ${err.message}`);
      await bankDb.run("ROLLBACK");
      return { success: false, error: err.message };
    }

}


export async function getAccount(userId) {
  try {
    let acc = await bankDb.get(`SELECT * FROM bankAccounts WHERE userId = ?`, [userId]);
    const name = await getName(acc.accountNumber, userId);
    acc.username = name;
    return acc || null;
  } catch (err) {
    logger.error(`Failed to fetch account for user ${userId}: ${err.message}`);
    return {success:false}
  }
}

export async function getName(accountNumber, reqUserId){
  try{
    const userId = await bankDb.get(`SELECT userId FROM bankAccounts WHERE accountNumber = ?`, [accountNumber]);
    if (!userId) return {success:false}
    if(!reqUserId) return null;
    const name = await getUsernameById(userId.userId);
    return name;
  }catch (_){
    return null;
  }
}

export async function searchAccounts(partialAccount, reqUserId) {
  const searchStr = String(partialAccount);

  // Require at least 10 characters to protect privacy
  if (searchStr.length < 10) return [];

  const search = searchStr + "%"; // prefix match

  // Fetch matching accounts
  const accounts = await bankDb.getAll(
    `SELECT accountNumber, userId FROM bankAccounts WHERE accountNumber LIKE ? LIMIT 5`,
    [search]
  );

  // Map to include names
  const results = await Promise.all(
    accounts.map(async (acc) => {
      const name = await getName(acc.accountNumber, reqUserId);
      return { accountNumber: acc.accountNumber, name };
    })
  );

  return results;
}


const SECRET_KEY = process.env.HMAC_SECRET || 'supersecretkey'; // store securely in env

// REQUEST MONEY
export async function requestMoney(fromUserId, toBankNumber, amount, expiryMinutes = 24*60) {
  if (!toBankNumber || amount <= 0 || amount > 999_999) {
    logger.warn(`Invalid money request amount ${amount} from user ${fromUserId}`);
    return { success: false, error: "Invalid request parameters. Max 999,999.00 allowed." };
  }

  const expiry = Date.now() + expiryMinutes * 60 * 1000; // expiry timestamp
  const payload = { toBankNumber, amount, expiry };
  const payloadString = JSON.stringify(payload);
  const signature = createHmac('sha256', SECRET_KEY)
    .update(payloadString)
    .digest('hex');

  const requestId = randomUUID();

  await bankDb.run(
    `INSERT INTO moneyRequests (id, fromUserId, toBankNumber, amount, expiry, signature, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [requestId, fromUserId, toBankNumber, amount, expiry, signature, Date.now()]
  );

  return { success: true, requestId, payload, signature };
}

export async function receiveMoney(requestId, senderUserId, payload, signature) {
  if (payload.amount > 999_999) {
    logger.warn(`Attempt to receive amount exceeding 999,999: ${payload.amount} by user ${senderUserId}`);
    return { success: false, error: "Transaction amount exceeds maximum allowed (999,999.00)." };
  }
  const reqRow = await bankDb.get(`SELECT * FROM moneyRequests WHERE id = ?`, [requestId]);
  if (!reqRow) return { success: false, error: "Request not found." };

  if (reqRow.status !== 'pending') {
    logger.warn(`Money request reused or already processed: ${requestId}`);
    return { success: false, error: "Request already processed." };
  }
  if (Date.now() > payload.expiry) {
    await bankDb.run(`UPDATE moneyRequests SET status='expired' WHERE id=?`, [requestId]);
    return { success: false, error: "Request expired." };
  }

  // Verify signature
  const expectedSignature = await bankDb.get(
    `SELECT * FROM moneyRequests WHERE id = ? AND signature = ?`,
    [requestId, signature]
  );

  if (!expectedSignature) {
    logger.warn(`Invalid signature for money request ${requestId}`);
    return { success: false, error: "Invalid Signature." };
  }

  // Get sender's account
  const senderAccount = await getAccount(senderUserId);
  if (!senderAccount) return { success: false, error: "Sender account not found." };
  if (senderAccount.balance < payload.amount) return { success: false, error: "Sender has insufficient balance." };
  
  try {
    // Atomic transaction
    await bankDb.run("BEGIN TRANSACTION");

    await bankDb.run(
      `UPDATE bankAccounts SET balance = balance - ? WHERE userId = ?`,
      [payload.amount, senderUserId]
    );

    await bankDb.run(
      `UPDATE bankAccounts SET balance = balance + ? WHERE accountNumber = ?`,
      [payload.amount, payload.toBankNumber]
    );

    await bankDb.run(`UPDATE moneyRequests SET status='completed' WHERE id=?`, [requestId]);

    await bankDb.run("COMMIT");
    return { success: true };
    } catch (err) {
      logger.warn(`Transaction rollback triggered: ${err.message}`);
      await bankDb.run("ROLLBACK");
      return { success: false, error: err.message };
    }

}

export async function getAllAccounts() {
  return await bankDb.getAll(`SELECT * FROM bankAccounts`);
}

export async function getAllMoneyRequests() {
  return await bankDb.getAll(`SELECT * FROM moneyRequests`);
}



function generateAccountNumber(length = 16) {
  let accountNumber = '';
  for (let i = 0; i < length; i++) {
    accountNumber += randomInt(0, 10); // secure random digit
  }
  return accountNumber;
}


