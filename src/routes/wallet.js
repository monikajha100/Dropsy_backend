const express = require("express");
const router = express.Router();
const pool = require("./pool");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// =====================================================
// CONFIGURATION
// =====================================================

const KEY_ID = process.env.RAZORPAY_KEY_ID?.trim();
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET?.trim();
const IS_PRODUCTION = process.env.NODE_ENV === "production";

console.log("RAZORPAY CONFIG CHECK:", {
  KEY_ID_PRESENT: Boolean(KEY_ID),
  KEY_SECRET_PRESENT: Boolean(KEY_SECRET),
  KEY_MODE: KEY_ID
    ? KEY_ID.startsWith("rzp_live_")
      ? "live"
      : KEY_ID.startsWith("rzp_test_")
      ? "test"
      : "unknown-format"
    : "missing",
});

const JWT_SECRET = process.env.JWT_SECRET;

const SUCCESS_STATUSES = ["success", "successful", "completed", "paid"];

const TRANSACTION_CATEGORIES = [
  "wallet_recharge",
  "shipping_order_fee",
  "shipping_charge",
  "platform_charge",
  "product_purchase",
  "package_plan",
  "refund",
  "admin_manual",
  "other",
];

function getRazorpay() {
  if (!KEY_ID || !KEY_SECRET) {
    throw new Error("Razorpay environment variables are missing.");
  }

  return new Razorpay({
    key_id: KEY_ID,
    key_secret: KEY_SECRET,
  });
}

// =====================================================
// RAZORPAY ERROR HELPER
// Razorpay's Node SDK throws a plain object like
// { statusCode, error: { code, description, ... } }
// so error.message is usually undefined.
// =====================================================

function getRazorpayErrorInfo(error) {
  const rzp = error?.error || {};

  return {
    status: error?.statusCode || null,
    code: rzp.code || error?.code || null,
    description: rzp.description || null,
    reason: rzp.reason || null,
    field: rzp.field || null,
    message: error?.message || null,
  };
}

function money(value) {
  return Number(Number(value || 0).toFixed(2));
}

function getRechargeAmountInPaise(value) {
  const amount = Number(value);

  if (
    value === undefined ||
    value === null ||
    value === "" ||
    !Number.isFinite(amount) ||
    amount < 1 ||
    amount > 100000
  ) {
    return null;
  }

  const paise = Math.round(amount * 100);

  if (!Number.isSafeInteger(paise)) return null;

  return paise;
}

// =====================================================
// ADMIN AUTHENTICATION
// =====================================================

function authenticateAdmin(req, res, next) {
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({
        success: false,
        message: "Admin JWT secret is not configured.",
      });
    }

    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Admin token required.",
      });
    }

    const decoded = jwt.verify(header.slice(7), JWT_SECRET);

    if (String(decoded.role || "").toLowerCase() !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required.",
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    console.error("WALLET ADMIN AUTH ERROR:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired admin token.",
    });
  }
}

// =====================================================
// SELLER AUTHENTICATION
// =====================================================

async function authenticateSeller(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Please log in to access your wallet.",
      });
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(match[1])
      .digest("hex");

    const [sessions] = await pool.query(
      `SELECT seller_id
       FROM seller_login_sessions
       WHERE session_token = ?
         AND expires_at > NOW()
         AND status = 'active'
       LIMIT 1`,
      [tokenHash]
    );

    if (!sessions.length) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please log in again.",
      });
    }

    req.sellerId = sessions[0].seller_id;
    next();
  } catch (error) {
    console.error("WALLET SELLER AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify seller session.",
    });
  }
}

// =====================================================
// COMMON HELPERS
// =====================================================

function validDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || "")) {
    return false;
  }

  const date = new Date(`${value}T00:00:00Z`);

  return (
    !Number.isNaN(date.getTime()) &&
    date.toISOString().slice(0, 10) === value
  );
}

function validateDateFilters(from, to) {
  if (from && !validDate(from)) {
    return "Invalid start date. Use YYYY-MM-DD.";
  }

  if (to && !validDate(to)) {
    return "Invalid end date. Use YYYY-MM-DD.";
  }

  if (from && to && from > to) {
    return "Start date cannot be after end date.";
  }

  return "";
}

function getCategory(value) {
  const category = String(value || "").trim().toLowerCase();

  if (!category) return "";

  if (!TRANSACTION_CATEGORIES.includes(category)) {
    return null;
  }

  return category;
}

function getDateConditions(from, to, column, params) {
  const conditions = [];

  if (from) {
    conditions.push(`${column} >= ?`);
    params.push(`${from} 00:00:00`);
  }

  if (to) {
    conditions.push(`${column} < DATE_ADD(?, INTERVAL 1 DAY)`);
    params.push(`${to} 00:00:00`);
  }

  return conditions;
}

async function getOrCreateWallet(connection, sellerId) {
  const [rows] = await connection.query(
    `SELECT id, seller_id, balance, currency, status
     FROM seller_wallet
     WHERE seller_id = ?
     LIMIT 1
     FOR UPDATE`,
    [sellerId]
  );

  if (rows.length) return rows[0];

  const [created] = await connection.query(
    `INSERT INTO seller_wallet
      (seller_id, balance, currency, status)
     VALUES (?, 0.00, 'INR', 'active')`,
    [sellerId]
  );

  return {
    id: created.insertId,
    seller_id: sellerId,
    balance: 0,
    currency: "INR",
    status: "active",
  };
}

// =====================================================
// SELLER: WALLET BALANCE
// GET /api/wallet/balance
// =====================================================

router.get("/balance", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, balance, currency, status
       FROM seller_wallet
       WHERE seller_id = ?
       LIMIT 1`,
      [req.sellerId]
    );

    const wallet = rows[0] || {
      balance: 0,
      currency: "INR",
      status: "inactive",
    };

    return res.json({
      success: true,
      wallet,
      balance: money(wallet.balance),
      currency: wallet.currency || "INR",
      status: wallet.status,
    });
  } catch (error) {
    console.error("WALLET BALANCE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load wallet balance.",
    });
  }
});

// =====================================================
// SELLER: WALLET PASSBOOK
// GET /api/wallet/passbook
// =====================================================

router.get("/passbook", authenticateSeller, async (req, res) => {
  try {
    const { from, to, search, type, category } = req.query;

    const dateError = validateDateFilters(from, to);

    if (dateError) {
      return res.status(400).json({
        success: false,
        message: dateError,
      });
    }

    const normalizedType = String(type || "").toLowerCase();

    if (normalizedType && !["credit", "debit"].includes(normalizedType)) {
      return res.status(400).json({
        success: false,
        message: "Type must be credit or debit.",
      });
    }

    const normalizedCategory = getCategory(category);

    if (normalizedCategory === null) {
      return res.status(400).json({
        success: false,
        message: "Invalid transaction category.",
      });
    }

    const [walletRows] = await pool.query(
      `SELECT id, balance, currency, status
       FROM seller_wallet
       WHERE seller_id = ?
       LIMIT 1`,
      [req.sellerId]
    );

    const wallet = walletRows[0] || {
      balance: 0,
      currency: "INR",
      status: "inactive",
    };

    const conditions = ["seller_id = ?"];
    const params = [req.sellerId];

    conditions.push(...getDateConditions(from, to, "created_at", params));

    if (normalizedType) {
      conditions.push("LOWER(transaction_type) = ?");
      params.push(normalizedType);
    }

    if (normalizedCategory) {
      conditions.push("LOWER(reference_type) = ?");
      params.push(normalizedCategory);
    }

    if (search && String(search).trim()) {
      const term = `%${String(search).trim()}%`;

      conditions.push(
        `(CAST(reference_id AS CHAR) LIKE ?
          OR reason LIKE ?
          OR CAST(payment_id AS CHAR) LIKE ?
          OR CAST(id AS CHAR) LIKE ?)`
      );

      params.push(term, term, term, term);
    }

    const [transactions] = await pool.query(
      `SELECT
         id,
         seller_id,
         wallet_id,
         transaction_type,
         amount,
         reason,
         reference_type,
         reference_id,
         payment_id,
         balance_before,
         balance_after,
         status,
         created_at
       FROM seller_transactions
       WHERE ${conditions.join(" AND ")}
       ORDER BY created_at DESC, id DESC
       LIMIT 500`,
      params
    );

    const [totals] = await pool.query(
      `SELECT
         COALESCE(SUM(
           CASE
             WHEN LOWER(transaction_type) = 'credit'
              AND LOWER(status) IN ('success','successful','completed','paid')
             THEN amount ELSE 0
           END
         ), 0) AS total_credit,

         COALESCE(SUM(
           CASE
             WHEN LOWER(transaction_type) = 'debit'
              AND LOWER(status) IN ('success','successful','completed','paid')
             THEN amount ELSE 0
           END
         ), 0) AS total_debit

       FROM seller_transactions
       WHERE seller_id = ?`,
      [req.sellerId]
    );

    return res.json({
      success: true,
      status: true,
      wallet,
      summary: {
        balance: money(wallet.balance),
        currency: wallet.currency || "INR",
        total_credit: money(totals[0].total_credit),
        total_debit: money(totals[0].total_debit),
      },
      transactions,
    });
  } catch (error) {
    console.error("SELLER PASSBOOK API ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load passbook.",
    });
  }
});

// =====================================================
// SELLER: CREATE WALLET RECHARGE ORDER
// POST /api/wallet/recharge/create-order
// =====================================================

router.post("/recharge/create-order", authenticateSeller, async (req, res) => {
  try {
    const amountInPaise = getRechargeAmountInPaise(req.body?.amount);

    if (!amountInPaise) {
      return res.status(400).json({
        success: false,
        message: "Recharge amount must be between ₹1 and ₹1,00,000.",
      });
    }

    const [walletRows] = await pool.query(
      `SELECT status
       FROM seller_wallet
       WHERE seller_id = ?
       LIMIT 1`,
      [req.sellerId]
    );

    if (walletRows[0]?.status === "blocked") {
      return res.status(403).json({
        success: false,
        message: "Your wallet is blocked. Please contact support.",
      });
    }

    const razorpay = getRazorpay();

    const order = await razorpay.orders.create({
      amount: amountInPaise,
      currency: "INR",
      receipt: `wr_${Date.now()}_${req.sellerId}`.slice(0, 40),
      notes: {
        package: "seller-wallet-recharge",
        seller_id: String(req.sellerId),
      },
    });

    if (
      !order.id ||
      order.amount !== amountInPaise ||
      order.currency !== "INR"
    ) {
      return res.status(502).json({
        success: false,
        message: "Unable to confirm recharge order.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Wallet recharge order created.",
      key_id: KEY_ID,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
    });
  } catch (error) {
    const info = getRazorpayErrorInfo(error);

    console.error("========== WALLET RECHARGE ERROR ==========");
    console.error("Seller ID:", req.sellerId);
    console.error("Razorpay Error Info:", info);
    console.error("Full Error:", error);
    console.error("============================================");

    // ===== TEMPORARY DEBUG RESPONSE =====
    // Shows the real reason in the browser popup.
    // After the problem is fixed, restore the safe production messages.
    const realReason =
      info.description ||
      error?.sqlMessage ||
      error?.message ||
      (error?.code ? `Error code: ${error.code}` : "") ||
      "Unknown error";

    return res.status(500).json({
      success: false,
      message: `[DEBUG] ${realReason}`,
      debug: {
        razorpay: info,
        code: error?.code || null,
        sqlMessage: error?.sqlMessage || null,
        keyMode: KEY_ID
          ? KEY_ID.startsWith("rzp_live_")
            ? "live"
            : KEY_ID.startsWith("rzp_test_")
            ? "test"
            : "unknown-format"
          : "missing",
      },
    });
  }
});

// =====================================================
// SELLER: VERIFY RECHARGE AND CREDIT WALLET
// POST /api/wallet/recharge/verify
// =====================================================

router.post("/recharge/verify", authenticateSeller, async (req, res) => {
  let connection;

  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
      req.body || {};

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature ||
      !/^[a-f0-9]{64}$/i.test(razorpay_signature)
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment verification details are missing or invalid.",
      });
    }

    if (!KEY_SECRET) {
      throw new Error("Razorpay secret is missing.");
    }

    const expectedSignature = crypto
      .createHmac("sha256", KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    const expectedBuffer = Buffer.from(expectedSignature, "hex");
    const receivedBuffer = Buffer.from(razorpay_signature, "hex");

    if (
      expectedBuffer.length !== receivedBuffer.length ||
      !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment signature.",
      });
    }

    const razorpay = getRazorpay();

    const [order, payment] = await Promise.all([
      razorpay.orders.fetch(razorpay_order_id),
      razorpay.payments.fetch(razorpay_payment_id),
    ]);

    if (
      order.id !== razorpay_order_id ||
      !Number.isSafeInteger(order.amount) ||
      order.amount <= 0 ||
      order.currency !== "INR" ||
      order.notes?.package !== "seller-wallet-recharge" ||
      String(order.notes?.seller_id) !== String(req.sellerId) ||
      payment.order_id !== razorpay_order_id ||
      payment.amount !== order.amount ||
      payment.currency !== "INR" ||
      payment.status !== "captured"
    ) {
      return res.status(400).json({
        success: false,
        message: "Recharge payment could not be verified.",
      });
    }

    const amount = money(order.amount / 100);

    if (amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid recharge amount.",
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Seller row lock prevents concurrent duplicate crediting.
    const [sellerRows] = await connection.query(
      `SELECT id
       FROM sellers
       WHERE id = ?
       LIMIT 1
       FOR UPDATE`,
      [req.sellerId]
    );

    if (!sellerRows.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message: "Seller account not found.",
      });
    }

    const [existingTransactions] = await connection.query(
      `SELECT id
       FROM seller_transactions
       WHERE payment_id = ?
       LIMIT 1`,
      [razorpay_payment_id]
    );

    if (existingTransactions.length) {
      const [currentWallet] = await connection.query(
        `SELECT balance
         FROM seller_wallet
         WHERE seller_id = ?
         LIMIT 1`,
        [req.sellerId]
      );

      await connection.commit();

      return res.status(200).json({
        success: true,
        already_credited: true,
        message: "This recharge has already been credited.",
        balance: money(currentWallet[0]?.balance || 0),
      });
    }

    const wallet = await getOrCreateWallet(connection, req.sellerId);

    if (wallet.status === "blocked") {
      await connection.rollback();

      return res.status(403).json({
        success: false,
        message: "Your wallet is blocked. Contact support.",
      });
    }

    const before = money(wallet.balance);
    const after = money(before + amount);

    await connection.query(
      `UPDATE seller_wallet
       SET balance = ?
       WHERE id = ?`,
      [after, wallet.id]
    );

    // reference_id is INT in your database.
    // Razorpay order ID is stored in reason, not reference_id.
    await connection.query(
      `INSERT INTO seller_transactions
        (
          seller_id,
          wallet_id,
          transaction_type,
          amount,
          reason,
          reference_type,
          reference_id,
          payment_id,
          balance_before,
          balance_after,
          status
        )
       VALUES (?, ?, 'credit', ?, ?, 'wallet_recharge', NULL, ?, ?, ?, 'success')`,
      [
        req.sellerId,
        wallet.id,
        amount,
        `Wallet recharge. Razorpay order: ${razorpay_order_id}`,
        razorpay_payment_id,
        before,
        after,
      ]
    );

    await connection.commit();

    return res.status(200).json({
      success: true,
      message: "Wallet recharge successful.",
      amount,
      balance_before: before,
      balance_after: after,
      payment_id: razorpay_payment_id,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("RECHARGE ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("WALLET RECHARGE VERIFY ERROR:", {
      razorpay: getRazorpayErrorInfo(error),
      full: error,
    });

    return res.status(500).json({
      success: false,
      message:
        "Wallet recharge verification failed. If money was deducted, contact support before paying again.",
    });
  } finally {
    if (connection) connection.release();
  }
});

// =====================================================
// ADMIN: ALL SELLERS AND WALLET BALANCES
// GET /api/wallet/admin/sellers
// =====================================================

router.get("/admin/sellers", authenticateAdmin, async (req, res) => {
  try {
    const [sellers] = await pool.query(
      `SELECT
         s.id AS seller_id,
         s.fullName AS seller_name,
         s.email,
         s.enrollmentNumber,
         COALESCE(w.balance, 0) AS balance,
         COALESCE(w.currency, 'INR') AS currency,
         COALESCE(w.status, 'inactive') AS wallet_status
       FROM sellers s
       LEFT JOIN seller_wallet w
         ON w.seller_id = s.id
       ORDER BY s.id DESC`
    );

    return res.json({
      success: true,
      count: sellers.length,
      sellers,
      data: sellers,
    });
  } catch (error) {
    console.error("ADMIN WALLET SELLERS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load seller wallets.",
    });
  }
});

// =====================================================
// ADMIN: ALL SELLER PASSBOOK
// GET /api/wallet/admin/passbook
// =====================================================

router.get("/admin/passbook", authenticateAdmin, async (req, res) => {
  try {
    const { from, to, search, seller_id, type, category } = req.query;

    const dateError = validateDateFilters(from, to);

    if (dateError) {
      return res.status(400).json({
        success: false,
        message: dateError,
      });
    }

    const conditions = ["1 = 1"];
    const params = [];

    conditions.push(...getDateConditions(from, to, "t.created_at", params));

    if (seller_id) {
      if (!/^\d+$/.test(String(seller_id))) {
        return res.status(400).json({
          success: false,
          message: "Invalid seller ID.",
        });
      }

      conditions.push("t.seller_id = ?");
      params.push(Number(seller_id));
    }

    if (type) {
      const normalizedType = String(type).toLowerCase();

      if (!["credit", "debit"].includes(normalizedType)) {
        return res.status(400).json({
          success: false,
          message: "Type must be credit or debit.",
        });
      }

      conditions.push("LOWER(t.transaction_type) = ?");
      params.push(normalizedType);
    }

    const normalizedCategory = getCategory(category);

    if (normalizedCategory === null) {
      return res.status(400).json({
        success: false,
        message: "Invalid transaction category.",
      });
    }

    if (normalizedCategory) {
      conditions.push("LOWER(t.reference_type) = ?");
      params.push(normalizedCategory);
    }

    if (search && String(search).trim()) {
      const term = `%${String(search).trim()}%`;

      conditions.push(
        `(s.fullName LIKE ?
          OR s.email LIKE ?
          OR s.enrollmentNumber LIKE ?
          OR t.reason LIKE ?
          OR CAST(t.reference_id AS CHAR) LIKE ?
          OR CAST(t.payment_id AS CHAR) LIKE ?
          OR CAST(t.id AS CHAR) LIKE ?)`
      );

      params.push(term, term, term, term, term, term, term);
    }

    const [transactions] = await pool.query(
      `SELECT
         t.id,
         t.seller_id,
         s.fullName AS seller_name,
         s.email AS seller_email,
         s.enrollmentNumber,
         t.wallet_id,
         t.transaction_type,
         t.amount,
         t.reason,
         t.reference_type,
         t.reference_id,
         t.payment_id,
         t.balance_before,
         t.balance_after,
         t.status,
         t.created_at
       FROM seller_transactions t
       LEFT JOIN sellers s ON s.id = t.seller_id
       WHERE ${conditions.join(" AND ")}
       ORDER BY t.created_at DESC, t.id DESC
       LIMIT 1000`,
      params
    );

    const [walletSummary] = await pool.query(
      `SELECT
         COUNT(*) AS total_sellers,
         COALESCE(SUM(balance), 0) AS balance
       FROM seller_wallet`
    );

    const [transactionSummary] = await pool.query(
      `SELECT
         COALESCE(SUM(
           CASE
             WHEN LOWER(transaction_type) = 'credit'
              AND LOWER(status) IN ('success','successful','completed','paid')
             THEN amount ELSE 0
           END
         ), 0) AS total_credit,

         COALESCE(SUM(
           CASE
             WHEN LOWER(transaction_type) = 'debit'
              AND LOWER(status) IN ('success','successful','completed','paid')
             THEN amount ELSE 0
           END
         ), 0) AS total_debit

       FROM seller_transactions`
    );

    return res.json({
      success: true,
      summary: {
        total_sellers: Number(walletSummary[0].total_sellers || 0),
        balance: money(walletSummary[0].balance),
        total_credit: money(transactionSummary[0].total_credit),
        total_debit: money(transactionSummary[0].total_debit),
      },
      count: transactions.length,
      transactions,
      data: transactions,
    });
  } catch (error) {
    console.error("ADMIN PASSBOOK API ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load admin passbook.",
    });
  }
});

// =====================================================
// ADMIN: MANUAL CREDIT / DEBIT
// POST /api/wallet/admin/adjust
// =====================================================

router.post("/admin/adjust", authenticateAdmin, async (req, res) => {
  let connection;

  try {
    const sellerId = Number(req.body?.seller_id);
    const amount = Number(req.body?.amount);
    const type = String(req.body?.transaction_type || "").toLowerCase();
    const reason = String(req.body?.reason || "").trim();

    if (!Number.isInteger(sellerId) || sellerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid seller ID is required.",
      });
    }

    if (!Number.isFinite(amount) || amount <= 0 || amount > 100000000) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid amount greater than zero.",
      });
    }

    if (!["credit", "debit"].includes(type)) {
      return res.status(400).json({
        success: false,
        message: "Transaction type must be credit or debit.",
      });
    }

    if (!reason || reason.length > 255) {
      return res.status(400).json({
        success: false,
        message: "Enter a reason (maximum 255 characters).",
      });
    }

    const roundedAmount = money(amount);

    if (roundedAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Amount must be greater than zero.",
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [sellerRows] = await connection.query(
      `SELECT id, fullName
       FROM sellers
       WHERE id = ?
       LIMIT 1
       FOR UPDATE`,
      [sellerId]
    );

    if (!sellerRows.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message: "Seller not found.",
      });
    }

    const wallet = await getOrCreateWallet(connection, sellerId);

    if (wallet.status === "blocked") {
      await connection.rollback();

      return res.status(403).json({
        success: false,
        message: "This seller wallet is blocked.",
      });
    }

    const before = money(wallet.balance);

    const after =
      type === "credit"
        ? money(before + roundedAmount)
        : money(before - roundedAmount);

    if (type === "debit" && after < 0) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message: "Insufficient wallet balance.",
        current_balance: before,
      });
    }

    await connection.query(
      `UPDATE seller_wallet
       SET balance = ?
       WHERE id = ?`,
      [after, wallet.id]
    );

    const [insertResult] = await connection.query(
      `INSERT INTO seller_transactions
        (
          seller_id,
          wallet_id,
          transaction_type,
          amount,
          reason,
          reference_type,
          reference_id,
          payment_id,
          balance_before,
          balance_after,
          status
        )
       VALUES (?, ?, ?, ?, ?, 'admin_manual', NULL, NULL, ?, ?, 'success')`,
      [sellerId, wallet.id, type, roundedAmount, reason, before, after]
    );

    await connection.commit();

    return res.status(201).json({
      success: true,
      message: `Wallet ${type} successful.`,
      transaction: {
        id: insertResult.insertId,
        seller_id: sellerId,
        seller_name: sellerRows[0].fullName,
        transaction_type: type,
        amount: roundedAmount,
        balance_before: before,
        balance_after: after,
        reason,
        reference_type: "admin_manual",
        status: "success",
      },
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("WALLET ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("ADMIN WALLET ADJUST ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to update seller wallet.",
    });
  } finally {
    if (connection) connection.release();
  }
});

// =====================================================
// EXPORT
// =====================================================

module.exports = router;