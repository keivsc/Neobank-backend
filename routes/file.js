import express from 'express';
import Logger from '../src/logging.js';
import { verifyToken } from '../services/session.js';
import { 
  createAccount, 
  addBalance, 
  deductBalance, 
  deleteAccount, 
  transferBalance, 
  getAccount,
  getName,
  searchAccounts,
  getAllMoneyRequests,
  getAllAccounts
} from '../services/bank.js';
import { randomInt } from 'crypto';

const router = express.Router();
const logger = new Logger('bank');
import { requestMoney, receiveMoney } from '../services/bank.js'; // import the new functions
import { requireDebugAuth } from '../src/utils.js';


// Authentication middleware
router.use(async (req, res, next) => {
  if (req.path === '/all') {
    return next();
  }
  const sessionToken = req.cookies['session'];
  const deviceId = req.cookies['x-device-id'];

  if (!sessionToken || !deviceId) {
    return res.status(401).json({ error: "Missing authentication cookies." });
  }

  const userId = await verifyToken(sessionToken, deviceId);
  if (!userId) {
    return res.status(401).json({ error: "Invalid session." });
  }

  req.userId = userId;
  next();
});

// CREATE account
router.post('/create', async (req, res) => {
  const { type } = req.body;
  if (!type) {
    return res.status(400).json({ error: "Missing type." });
  }

  const result = await createAccount( type, req.userId);
  return res.status(result.success ? 200 : 400).json(result);
});

// DELETE account
router.delete('/delete', async (req, res) => {
  const result = await deleteAccount(req.userId);
  return res.status(result.success ? 200 : 404).json(result);
});

// TRANSFER balance
router.put('/transfer', async (req, res) => {
  const { accountNumber, amount } = req.body;
  if (!accountNumber || !amount || amount <= 0) {
    return res.status(400).json({ error: "Missing or invalid transfer details." });
  }

  const result = await transferBalance(req.userId, accountNumber, amount);
  return res.status(result.success ? 200 : 400).json(result);
});

// GET user's account (balance/info)
// GET user's account (balance/info), create if none exists
router.get('/me', async (req, res) => {
  try {
    let acc = await createAccount('savings', req.userId);

    return res.status(200).json(acc);
  } catch (err) {
    return res.status(500).json({ error: "Internal server error." });
  }
});

router.get('/name/:accountNumber', async(req, res)=>{
  const accountNumber = req.params.accountNumber;
  if(!accountNumber){
    return res.status(400).json({error:"Missing Account Number."});
  }

  const name = await getName(accountNumber, req.userId);
  if(!name){
    return res.status(400).json({error:"Invalid Account Number."})
  }
  return res.status(200).json({name})
})

// GET /search/:accountNumber
router.get('/search/:accountNumber', async (req, res) => {
  const partialAccount = req.params.accountNumber;
  if (!partialAccount) {
    return res.status(400).json({ error: "Missing account number." });
  }

  try {
    const results = await searchAccounts(partialAccount, req.userId);
    if (results.length === 0) {
      return res.status(404).json({ error: "No matching accounts found." });
    }
    return res.status(200).json({ accounts: results });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error." });
  }
});


// SEND / RECEIVE MONEY using a request (via QR)
router.post('/send/:requestId', async (req, res) => {
  const { requestId } = req.params;
  const { payload, signature } = req.body;

  if (!requestId) {
    return res.status(400).json({ error: "Missing request ID." });
  }
  if (!payload || !signature) {
    return res.status(400).json({ error: "Missing payload or signature." });
  }

  try {
    // Use logged-in user as the recipient
    const result = await receiveMoney(requestId, req.userId, payload, signature);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    return res.status(200).json({ success:true, message: "Money received successfully." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error." });
  }
});



// CREATE a money request
router.post('/request', async (req, res) => {
  const { toBankNumber, amount } = req.body;
  if (!toBankNumber || !amount || amount <= 0) {
    return res.status(400).json({ error: "Invalid request parameters." });
  }

  try {
    const result = await requestMoney(req.userId, toBankNumber, amount);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    // Combine everything into a single object for QR encoding
    const qrData = {
      requestId: result.requestId,
      toBankNumber: result.payload.toBankNumber,
      amount: result.payload.amount,
      expiry: result.payload.expiry,
      signature: result.signature
    };

    // Optionally, convert to a string for QR
    const qrString = JSON.stringify(qrData);

    return res.status(200).json({
      success:true,
      message: "Money request created successfully.",
      requestId:result.requestId,
      qr: qrString // this can be fed directly to a QR generator
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error." });
  }
});


router.get('/all', requireDebugAuth, async (req, res) => {
  const accounts = await getAllAccounts();
  const requests = await getAllMoneyRequests();

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Bank Debug</title>
      <style>
        body {
          font-family: system-ui;
          background: #0f172a;
          color: #e5e7eb;
          padding: 20px;
        }
        h2 {
          margin-top: 40px;
          color: #38bdf8;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          background: #020617;
          border-radius: 8px;
          overflow: hidden;
        }
        th, td {
          padding: 10px 14px;
          border-bottom: 1px solid #1e293b;
          text-align: left;
          font-size: 14px;
        }
        th {
          position: sticky;
          top: 0;
          background: #020617;
        }
      </style>
    </head>
    <body>
      <h1>Bank Debug Tables</h1>

      ${renderTable('Bank Accounts', accounts)}
      ${renderTable('Money Requests', requests)}

    </body>
    </html>
  `);
});

function renderTable(title, rows) {
  if (!rows.length) return `<h2>${title}</h2><p>No data</p>`;

  const headers = Object.keys(rows[0]);

  return `
    <h2>${title}</h2>
    <table>
      <thead>
        <tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>
      </thead>
      <tbody>
        ${rows.map(r => `
          <tr>
            ${headers.map(h => `<td>${r[h]}</td>`).join('')}
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}


export default router;



