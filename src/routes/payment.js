const express = require("express");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const jwt = require("jsonwebtoken");
const pool = require("./pool");

const router = express.Router();

// ======================================================
// CONFIGURATION
// ======================================================

const KEY_ID = process.env.RAZORPAY_KEY_ID;
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.warn("WARNING: JWT_SECRET is missing. Admin routes are disabled.");
}

const PACKAGE_VALIDITY_DAYS = 365;

const TYPE_TITLES = {
  national: "National",
  international: "International",
  website: "Website",
};

// ======================================================
// COMMON HELPERS
// ======================================================

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

function money(value) {
  return Number(Number(value || 0).toFixed(2));
}

function getAmountInPaise(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const amount = Number(value);

  if (
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !Number.isSafeInteger(Math.round(amount * 100))
  ) {
    return null;
  }

  return Math.round(amount * 100);
}

function getWholeRupeeAmountInPaise(value) {
  const amount = Number(value);

  if (
    value === undefined ||
    value === null ||
    value === "" ||
    !Number.isSafeInteger(amount) ||
    amount <= 0
  ) {
    return null;
  }

  return amount * 100;
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

  return Math.round(amount * 100);
}

function getRazorpay() {
  if (!KEY_ID || !KEY_SECRET) {
    throw new Error("Razorpay environment variables are missing.");
  }

  return new Razorpay({
    key_id: KEY_ID,
    key_secret: KEY_SECRET,
  });
}

function verifyRazorpaySignature(orderId, paymentId, signature) {
  if (!KEY_SECRET) {
    throw new Error("Razorpay secret is missing.");
  }

  const expected = crypto
    .createHmac("sha256", KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  const received = String(signature || "");

  if (!/^[a-f0-9]{64}$/i.test(received)) {
    return false;
  }

  const expectedBuffer = Buffer.from(expected, "hex");
  const receivedBuffer = Buffer.from(received, "hex");

  return (
    expectedBuffer.length === receivedBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, receivedBuffer)
  );
}

function getEnrollmentDate() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).formatToParts(new Date());

  const values = {};

  for (const part of parts) {
    if (part.type !== "literal") {
      values[part.type] = part.value;
    }
  }

  return `${values.day}${values.month}${values.year}`;
}

function validSellerData(data) {
  if (!data || typeof data !== "object") return false;

  const requiredValid = Boolean(
    clean(data.fullName) &&
    /^\d{10}$/.test(clean(data.mobile)) &&
    /^\S+@\S+\.\S+$/.test(clean(data.email)) &&
    clean(data.address) &&
    clean(data.city) &&
    clean(data.state)
  );

  const gst = clean(data.gstNumber);
  const gstValid = !gst || /^[0-9A-Z]{15}$/.test(gst);

  return requiredValid && gstValid;
}

function sellerDataFromNotes(notes = {}) {
  return {
    fullName: clean(notes.fullName),
    mobile: clean(notes.mobile),
    altMobile: clean(notes.altMobile),
    email: clean(notes.email).toLowerCase(),
    gstNumber: clean(notes.gstNumber).toUpperCase(),
    whatsapp: clean(notes.whatsapp),
    address: clean(notes.address),
    city: clean(notes.city),
    state: clean(notes.state),
    pincode: clean(notes.pincode),
  };
}

// ======================================================
// DATE HELPERS
// ======================================================

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

// ======================================================
// SELLER AUTHENTICATION
// ======================================================

async function authenticateSeller(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Please log in to continue.",
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
    console.error("SELLER AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify seller session.",
    });
  }
}

// ======================================================
// ADMIN AUTHENTICATION
// ======================================================

function authenticateAdmin(req, res, next) {
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({
        success: false,
        message: "Server auth is not configured.",
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
    console.error("ADMIN AUTH ERROR:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired admin token.",
    });
  }
}

// ======================================================
// SELLER REGISTRATION PAYMENT
// POST /api/payment/pay
// ======================================================

router.post("/pay", async (req, res) => {
  try {
    const data = {
      fullName: clean(req.body?.sellerData?.fullName),
      mobile: clean(req.body?.sellerData?.mobile),
      altMobile: clean(req.body?.sellerData?.altMobile),
      email: clean(req.body?.sellerData?.email).toLowerCase(),
      gstNumber: clean(req.body?.sellerData?.gstNumber).toUpperCase(),
      whatsapp: clean(req.body?.sellerData?.whatsapp),
      address: clean(req.body?.sellerData?.address),
      city: clean(req.body?.sellerData?.city),
      state: clean(req.body?.sellerData?.state),
      pincode: clean(req.body?.sellerData?.pincode),
    };

    const amountInPaise = getWholeRupeeAmountInPaise(
      req.body?.amount
    );

    if (!validSellerData(data)) {
      return res.status(400).json({
        success: false,
        message: "Please enter all required seller details correctly.",
      });
    }

    if (amountInPaise === null) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid positive whole-rupee amount.",
      });
    }

    if (data.pincode && !/^\d{6}$/.test(data.pincode)) {
      return res.status(400).json({
        success: false,
        message: "PIN code must be exactly 6 digits.",
      });
    }

    const [existing] = await pool.query(
      `SELECT id
       FROM sellers
       WHERE mobile = ? OR LOWER(email) = ?
       LIMIT 1`,
      [data.mobile, data.email]
    );

    if (existing.length) {
      return res.status(409).json({
        success: false,
        message: "This mobile number or email is already registered.",
      });
    }

    const razorpay = getRazorpay();

    const order = await razorpay.orders.create({
      amount: amountInPaise,
      currency: "INR",
      receipt: `seller_${Date.now()}`,
      notes: {
        package: "seller-registration",
        fullName: data.fullName,
        mobile: data.mobile,
        altMobile: data.altMobile,
        email: data.email,
        gstNumber: data.gstNumber,
        whatsapp: data.whatsapp,
        address: data.address,
        city: data.city,
        state: data.state,
        pincode: data.pincode,
      },
    });

    if (
      !order.id ||
      order.amount !== amountInPaise ||
      order.currency !== "INR"
    ) {
      return res.status(502).json({
        success: false,
        message: "Payment amount mismatch. Please contact support.",
      });
    }

    return res.json({
      success: true,
      message: "Payment order created.",
      key_id: KEY_ID,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
    });
  } catch (error) {
    console.error("REGISTRATION ORDER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create payment order.",
    });
  }
});

// ======================================================
// SELLER REGISTRATION PAYMENT VERIFICATION
// POST /api/payment/payment-success
// ======================================================

router.post("/payment-success", async (req, res) => {
  let connection;

  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
    } = req.body || {};

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment verification details are missing.",
      });
    }

    if (
      !verifyRazorpaySignature(
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      )
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
      order.notes?.package !== "seller-registration" ||
      payment.order_id !== razorpay_order_id ||
      payment.amount !== order.amount ||
      payment.currency !== order.currency ||
      payment.status !== "captured"
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment could not be verified as successful.",
      });
    }

    const data = sellerDataFromNotes(order.notes);

    if (!validSellerData(data)) {
      return res.status(400).json({
        success: false,
        message: "Seller details in payment order are invalid.",
      });
    }

    if (data.pincode && !/^\d{6}$/.test(data.pincode)) {
      return res.status(400).json({
        success: false,
        message: "Invalid PIN code in payment order.",
      });
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS seller_enrollment_sequence (
        id INT NOT NULL PRIMARY KEY,
        last_serial INT NOT NULL
      )
    `);

    await pool.query(`
      INSERT IGNORE INTO seller_enrollment_sequence (id, last_serial)
      VALUES (1, 100)
    `);

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [existing] = await connection.query(
      `SELECT id, enrollmentNumber
       FROM sellers
       WHERE mobile = ? OR LOWER(email) = ?
       LIMIT 1
       FOR UPDATE`,
      [data.mobile, data.email]
    );

    if (existing.length) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "This email or mobile is already registered. If payment was completed, contact support before paying again.",
      });
    }

    const [sequenceRows] = await connection.query(
      `SELECT last_serial
       FROM seller_enrollment_sequence
       WHERE id = 1
       FOR UPDATE`
    );

    if (!sequenceRows.length) {
      throw new Error("Enrollment sequence could not be loaded.");
    }

    const serial = Number(sequenceRows[0].last_serial) + 1;
    const enrollmentNumber = `DS${getEnrollmentDate()}_${serial}`;

    await connection.query(
      `UPDATE seller_enrollment_sequence
       SET last_serial = ?
       WHERE id = 1`,
      [serial]
    );

    const [insertResult] = await connection.query(
      `INSERT INTO sellers (
        enrollmentNumber,
        fullName,
        mobile,
        altMobile,
        email,
        gstNumber,
        whatsapp,
        address,
        city,
        state,
        pincode,
        payment_status,
        enrollment_generated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'paid', 1)`,
      [
        enrollmentNumber,
        data.fullName,
        data.mobile,
        data.altMobile || null,
        data.email,
        data.gstNumber || null,
        data.whatsapp || null,
        data.address,
        data.city,
        data.state,
        data.pincode || null,
      ]
    );

    await connection.commit();

    return res.status(200).json({
      success: true,
      message: "Payment verified and seller registration completed.",
      seller: {
        id: insertResult.insertId,
        enrollmentNumber,
        fullName: data.fullName,
        email: data.email,
        gstNumber: data.gstNumber || null,
        payment_status: "paid",
      },
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("REGISTRATION ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("PAYMENT VERIFICATION ERROR:", error);

    return res.status(500).json({
      success: false,
      message:
        "Payment verification failed. If money was deducted, contact support before retrying.",
    });
  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// PACKAGE HELPERS
// ======================================================

function slug(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function parseFeatures(value) {
  if (!value) return [];

  if (Array.isArray(value)) return value;

  try {
    return JSON.parse(value);
  } catch {
    return String(value)
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
}

function formatPackagePlan(row) {
  return {
    id: row.package_id,
    package_id: row.package_id,
    type: row.package_type,
    package_type: row.package_type,
    name: row.plan_name,
    plan_name: row.plan_name,
    price: money(row.price),
    gstAmount: money(row.gst_amount),
    gst_amount: money(row.gst_amount),
    total: money(row.total_amount),
    total_amount: money(row.total_amount),
    paymentTotal: money(row.total_amount),
    displayPrice: row.display_price || `₹${money(row.price)}`,
    displayTotal: row.display_total || `₹${money(row.total_amount)}`,
    theme: row.theme || "blue",
    badge: row.badge || "",
    note: row.note || "",
    tag: row.tag || "",
    features: parseFeatures(row.features),
    status: row.status,
    sort_order: Number(row.sort_order || 0),
  };
}

async function findPackagePlan(type, planId) {
  const normalizedType = clean(type).toLowerCase();
  const normalizedPlanId = clean(planId);

  if (
    !Object.prototype.hasOwnProperty.call(TYPE_TITLES, normalizedType) ||
    !normalizedPlanId
  ) {
    return null;
  }

  const [rows] = await pool.query(
    `SELECT
       id,
       package_id,
       package_type,
       plan_name,
       tag,
       price,
       gst_amount,
       total_amount,
       display_price,
       display_total,
       theme,
       badge,
       note,
       features,
       status,
       sort_order
     FROM seller_package_plans
     WHERE package_type = ?
       AND status = 'active'
     ORDER BY sort_order ASC, id ASC`,
    [normalizedType]
  );

  const requested = slug(normalizedPlanId);

  return (
    rows.find((row) => {
      return (
        slug(row.package_id) === requested ||
        slug(row.plan_name) === requested ||
        slug(`${normalizedType}_${row.plan_name}`) === requested
      );
    }) || null
  );
}

// ======================================================
// PACKAGE PASSBOOK HELPER
// Direct Razorpay payment is recorded in Passbook.
// Wallet balance is NOT deducted.
// ======================================================

async function recordPackagePassbookEntry(
  connection,
  sellerId,
  paymentRecord,
  razorpayPaymentId
) {
  // Avoid duplicate Passbook entry for the same Razorpay payment.
  const [existing] = await connection.query(
    `SELECT id
     FROM seller_transactions
     WHERE seller_id = ?
       AND payment_id = ?
       AND reference_type = 'package_plan'
     LIMIT 1
     FOR UPDATE`,
    [sellerId, razorpayPaymentId]
  );

  if (existing.length) {
    return existing[0].id;
  }

  // Lock latest wallet. Create a zero-balance wallet if none exists.
  const [walletRows] = await connection.query(
    `SELECT id, balance
     FROM seller_wallet
     WHERE seller_id = ?
     ORDER BY id DESC
     LIMIT 1
     FOR UPDATE`,
    [sellerId]
  );

  let wallet = walletRows[0];

  if (!wallet) {
    const [createdWallet] = await connection.query(
      `INSERT INTO seller_wallet
       (seller_id, balance, currency, status)
       VALUES (?, 0.00, 'INR', 'active')`,
      [sellerId]
    );

    wallet = {
      id: createdWallet.insertId,
      balance: 0,
    };
  }

  const unchangedBalance = money(wallet.balance);
  const packageAmount = money(paymentRecord.amount);
  const packageName =
    paymentRecord.package_name || "Package Plan";

  const reason =
    `Package Plan Purchase: ${packageName}`;

  const [result] = await connection.query(
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
     VALUES (?, ?, 'debit', ?, ?, 'package_plan', ?, ?, ?, ?, 'success')`,
    [
      sellerId,
      wallet.id,
      packageAmount,
      reason,
      Number(paymentRecord.id),
      razorpayPaymentId,
      unchangedBalance,
      unchangedBalance,
    ]
  );

  return result.insertId;
}

// ======================================================
// GET PACKAGE PLANS
// GET /api/payment/package/plans
// ======================================================

router.get("/package/plans", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         id,
         package_id,
         package_type,
         plan_name,
         tag,
         price,
         gst_amount,
         total_amount,
         display_price,
         display_total,
         theme,
         badge,
         note,
         features,
         status,
         sort_order
       FROM seller_package_plans
       WHERE status = 'active'
       ORDER BY
         FIELD(package_type, 'national', 'international', 'website'),
         sort_order ASC,
         id ASC`
    );

    const plans = rows.map(formatPackagePlan);

    const grouped = {
      national: plans.filter((p) => p.type === "national"),
      international: plans.filter((p) => p.type === "international"),
      website: plans.filter((p) => p.type === "website"),
    };

    return res.json({
      success: true,
      plans,
      data: grouped,
    });
  } catch (error) {
    console.error("PACKAGE PLANS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load package plans.",
    });
  }
});

// ======================================================
// GET CURRENT SELLER PACKAGE
// GET /api/payment/my-package
// ======================================================

router.get("/my-package", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         sub.id,
         sub.seller_id,
         sub.package_id,
         sub.package_name,
         sub.package_type,
         sub.payment_record_id,
         sub.status,
         sub.starts_at,
         sub.expires_at,
         sub.created_at,
         pp.plan_name,
         pp.price,
         pp.gst_amount,
         pp.total_amount,
         pp.display_price,
         pp.display_total,
         pp.features,
         pay.payment_id,
         pay.order_id,
         pay.payment_status
       FROM seller_package_subscriptions sub
       LEFT JOIN seller_package_plans pp
         ON pp.package_id = sub.package_id
        AND pp.package_type = sub.package_type
       LEFT JOIN seller_payments pay
         ON pay.id = sub.payment_record_id
       WHERE sub.seller_id = ?
         AND sub.status = 'active'
         AND (
           sub.expires_at IS NULL
           OR sub.expires_at > NOW()
         )
       ORDER BY sub.id DESC
       LIMIT 1`,
      [req.sellerId]
    );

    const currentPackage = rows[0] || null;

    return res.json({
      success: true,
      package: currentPackage,
      data: currentPackage,
    });
  } catch (error) {
    console.error("MY PACKAGE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load current package.",
    });
  }
});

// ======================================================
// GET ALL ACTIVE PACKAGES OF SELLER (for Combo Pack page)
// GET /api/payment/my-packages
//
// Returns every active, non-expired subscription with its
// plan features and the amount actually paid.
// expires_at = NULL means lifetime plan.
// ======================================================

router.get("/my-packages", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         sub.id,
         sub.package_id,
         sub.package_name,
         sub.package_type,
         sub.status,
         sub.starts_at,
         sub.expires_at,
         pp.plan_name,
         pp.features,
         pay.amount AS paid_amount
       FROM seller_package_subscriptions sub
       LEFT JOIN seller_package_plans pp
         ON pp.package_id = sub.package_id
        AND pp.package_type = sub.package_type
       LEFT JOIN seller_payments pay
         ON pay.id = sub.payment_record_id
       WHERE sub.seller_id = ?
         AND sub.status = 'active'
         AND (sub.expires_at IS NULL OR sub.expires_at > NOW())
       ORDER BY sub.starts_at ASC, sub.id ASC`,
      [req.sellerId]
    );

    const packages = rows.map((row) => ({
      id: row.id,
      package_id: row.package_id,
      package_name: row.package_name,
      plan_name: row.plan_name || row.package_name,
      package_type: row.package_type,
      status: row.status,
      starts_at: row.starts_at,
      expires_at: row.expires_at,
      paid_amount: money(row.paid_amount),
      features: parseFeatures(row.features),
    }));

    return res.json({
      success: true,
      count: packages.length,
      packages,
    });
  } catch (error) {
    console.error("MY PACKAGES ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load your packages.",
    });
  }
});

// ======================================================
// WALLET-BASED PACKAGE PURCHASE / UPGRADE
// ======================================================

// ------------------------------------------------------
// HELPER: how much should this seller pay for this plan?
//
// - No active plan of this type  -> full plan price
// - Active plan of this type     -> new price - amount already
//                                   paid for the current plan
//                                   (only difference is charged)
// - Same plan                    -> state "current" (blocked)
// - Cheaper/equal plan           -> state "lower"   (blocked)
//
// A seller can hold one active plan PER TYPE
// (national / international / website).
// ------------------------------------------------------


async function getPackageCharge(db, sellerId, plan, lock = false) {
  const planTotal = money(plan.total_amount);

  const [rows] = await db.query(
    `SELECT
       sub.id,
       sub.package_id,
       sub.package_name,
       sub.expires_at,
       COALESCE(pay.amount, 0) AS paid_amount
     FROM seller_package_subscriptions sub
     LEFT JOIN seller_payments pay
       ON pay.id = sub.payment_record_id
      AND pay.payment_status = 'success'
     WHERE sub.seller_id = ?
       AND sub.package_type = ?
       AND sub.status = 'active'
       AND (sub.expires_at IS NULL OR sub.expires_at > NOW())
     ORDER BY sub.id DESC
     LIMIT 1
     ${lock ? "FOR UPDATE" : ""}`,
    [sellerId, plan.package_type]
  );

  const current = rows[0] || null;
  const credit = current ? money(current.paid_amount) : 0;

  let state = "buy";

  if (current) {
    if (
      String(current.package_id) === String(plan.package_id)
    ) {
      state = "current";
    } else if (planTotal <= credit) {
      state = "lower";
    } else {
      state = "upgrade";
    }
  }

  const charge = current
    ? money(Math.max(planTotal - credit, 0))
    : planTotal;

  return {
    current,
    planTotal,
    credit,
    charge,
    state,
  };
}


// ======================================================
// QUOTES (price this seller will actually pay per plan)
// GET /api/payment/package/quotes?type=national
// ======================================================


router.get("/package/quotes", authenticateSeller, async (req, res) => {
  try {
    const type = clean(req.query?.type).toLowerCase();

    if (!Object.prototype.hasOwnProperty.call(TYPE_TITLES, type)) {
      return res.status(400).json({
        success: false,
        message: "Invalid package type.",
      });
    }

    const [plans] = await pool.query(
      `SELECT
         id,
         package_id,
         package_type,
         plan_name,
         total_amount
       FROM seller_package_plans
       WHERE package_type = ?
         AND status = 'active'
       ORDER BY sort_order ASC, id ASC`,
      [type]
    );

    const [walletRows] = await pool.query(
      `SELECT balance, status
       FROM seller_wallet
       WHERE seller_id = ?
       ORDER BY id DESC
       LIMIT 1`,
      [req.sellerId]
    );

    const balance = money(walletRows[0]?.balance || 0);
    const quotes = [];

    for (const plan of plans) {
      const q = await getPackageCharge(
        pool,
        req.sellerId,
        plan,
        false
      );

      quotes.push({
        package_id: plan.package_id,
        plan_key: slug(plan.plan_name),
        plan_name: plan.plan_name,
        state: q.state,
        plan_total: q.planTotal,
        credit: q.credit,
        charge: q.charge,
        shortfall:
          q.state === "buy" || q.state === "upgrade"
            ? money(Math.max(q.charge - balance, 0))
            : 0,
      });
    }

    return res.json({
      success: true,
      balance,
      wallet_status: walletRows[0]?.status || "inactive",
      quotes,
    });
  } catch (error) {
    console.error("PACKAGE QUOTES ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load package prices.",
    });
  }
});

// ======================================================
// BUY / UPGRADE PACKAGE FROM WALLET
// POST /api/payment/package/purchase-with-wallet
// body: { type, planId }
// ======================================================


router.post(
  "/package/purchase-with-wallet",
  authenticateSeller,
  async (req, res) => {
    let connection;

    try {
      const type = clean(req.body?.type).toLowerCase();
      const planId = clean(req.body?.planId);

      if (!TYPE_TITLES[type] || !planId) {
        return res.status(400).json({
          success: false,
          message: "Valid package type and plan are required.",
        });
      }

      connection = await pool.getConnection();
      await connection.beginTransaction();

      // Lock seller row to prevent simultaneous purchases.
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

      // Fetch selected active plan.
      const normalizedPlanId = slug(planId);

      const [planRows] = await connection.query(
        `SELECT
           id,
           package_id,
           package_type,
           plan_name,
           total_amount
         FROM seller_package_plans
         WHERE package_type = ?
           AND status = 'active'
         ORDER BY sort_order ASC, id ASC`,
        [type]
      );

      const plan = planRows.find(
        (row) =>
          slug(row.package_id) === normalizedPlanId ||
          slug(row.plan_name) === normalizedPlanId ||
          slug(`${type}_${row.plan_name}`) === normalizedPlanId
      );

      if (!plan) {
        await connection.rollback();

        return res.status(404).json({
          success: false,
          message: "Selected package was not found or is inactive.",
        });
      }

      const planTotal = money(plan.total_amount);

      if (planTotal <= 0) {
        await connection.rollback();

        return res.status(400).json({
          success: false,
          message: "Invalid package amount.",
        });
      }

      // Calculate the actual amount payable.
      const quote = await getPackageCharge(
        connection,
        req.sellerId,
        plan,
        true
      );

      if (quote.state === "current") {
        await connection.rollback();

        return res.status(409).json({
          success: false,
          message: "This package is already active.",
        });
      }

      if (quote.state === "lower" || quote.charge <= 0) {
        await connection.rollback();

        return res.status(400).json({
          success: false,
          message: "You cannot downgrade to a lower or equal package.",
        });
      }

      // Lock wallet.
      const [walletRows] = await connection.query(
        `SELECT id, balance, status
         FROM seller_wallet
         WHERE seller_id = ?
         ORDER BY id DESC
         LIMIT 1
         FOR UPDATE`,
        [req.sellerId]
      );

      const wallet = walletRows[0];

      if (!wallet || wallet.status !== "active") {
        await connection.rollback();

        return res.status(402).json({
          success: false,
          code: "INSUFFICIENT_BALANCE",
          message: "Please recharge your wallet before purchasing a package.",
          required: quote.charge,
          balance: money(wallet?.balance || 0),
          shortfall: quote.charge,
        });
      }

      if (wallet.status === "blocked") {
        await connection.rollback();

        return res.status(403).json({
          success: false,
          message: "Your wallet is blocked. Please contact support.",
        });
      }

      const before = money(wallet.balance);
      const charge = money(quote.charge);

      if (before < charge) {
        await connection.rollback();

        return res.status(402).json({
          success: false,
          code: "INSUFFICIENT_BALANCE",
          message: "Insufficient wallet balance. Please recharge your wallet.",
          required: charge,
          balance: before,
          shortfall: money(charge - before),
        });
      }

      const after = money(before - charge);
      const packageName =
        `${TYPE_TITLES[type]} - ${plan.plan_name}`;

      const orderReference =
        `WALLET_${req.sellerId}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;

      // 1. Record package payment.
      const [paymentResult] = await connection.query(
        `INSERT INTO seller_payments
          (
            seller_id,
            package_id,
            package_name,
            amount,
            payment_gateway,
            payment_id,
            order_id,
            payment_status,
            payment_date
          )
         VALUES (?, ?, ?, ?, 'wallet', NULL, ?, 'success', NOW())`,
        [
          req.sellerId,
          plan.package_id,
          packageName,
          charge,
          orderReference,
        ]
      );

      const paymentRecordId = paymentResult.insertId;

      // 2. Deduct wallet balance.
      await connection.query(
        `UPDATE seller_wallet
         SET balance = ?
         WHERE id = ?`,
        [after, wallet.id]
      );

      // 3. Insert exactly one debit passbook transaction.
      const reason =
        quote.state === "upgrade"
          ? `Package Upgrade: ${packageName}`
          : `Package Plan Purchase: ${packageName}`;

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
         VALUES (?, ?, 'debit', ?, ?, 'package_plan', ?, NULL, ?, ?, 'success')`,
        [
          req.sellerId,
          wallet.id,
          charge,
          reason.slice(0, 255),
          paymentRecordId,
          before,
          after,
        ]
      );

      // 4. Cancel previous active plan of the same type.
      await connection.query(
        `UPDATE seller_package_subscriptions
         SET status = 'cancelled'
         WHERE seller_id = ?
           AND package_type = ?
           AND status = 'active'`,
        [req.sellerId, type]
      );

      // 5. Activate new package.
      const [subscriptionResult] = await connection.query(
        `INSERT INTO seller_package_subscriptions
          (
            seller_id,
            package_id,
            package_name,
            package_type,
            payment_record_id,
            status,
            starts_at,
            expires_at
          )
         VALUES (
           ?, ?, ?, ?, ?, 'active',
           NOW(),
           DATE_ADD(NOW(), INTERVAL ? DAY)
         )`,
        [
          req.sellerId,
          plan.package_id,
          packageName,
          type,
          paymentRecordId,
          PACKAGE_VALIDITY_DAYS,
        ]
      );

      const [subscriptionRows] = await connection.query(
        `SELECT
           id,
           package_id,
           package_name,
           package_type,
           payment_record_id,
           status,
           starts_at,
           expires_at
         FROM seller_package_subscriptions
         WHERE id = ?
         LIMIT 1`,
        [subscriptionResult.insertId]
      );

      await connection.commit();

      return res.status(200).json({
        success: true,
        message:
          quote.state === "upgrade"
            ? "Package upgraded successfully."
            : "Package activated successfully.",
        charged: charge,
        plan_total: quote.planTotal,
        previous_paid: quote.credit,
        balance_before: before,
        balance_after: after,
        package: subscriptionRows[0],
      });
    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch (rollbackError) {
          console.error("PACKAGE WALLET ROLLBACK ERROR:", rollbackError);
        }
      }

      console.error("PACKAGE WALLET PURCHASE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to purchase package from wallet.",
      });
    } finally {
      if (connection) connection.release();
    }
  }
);


// ======================================================
// FEATURE GATING FOR SELLER PANEL ROUTES
//
// Usage in any seller route:
//   router.get("/something", authenticateSeller,
//     requirePackagePlan(["advance", "royal"]), handler);
//
//   requirePackagePlan()  -> any active, non-expired plan
//
// Expired plans are blocked automatically because
// the query checks expires_at > NOW().
// ======================================================

function requirePackagePlan(allowedPlans = [], allowedTypes = []) {
  const plans = allowedPlans.map(slug);
  const types = allowedTypes.map((t) => String(t).toLowerCase());

  return async (req, res, next) => {
    try {
      const [rows] = await pool.query(
        `SELECT sub.package_type, sub.expires_at, pp.plan_name
         FROM seller_package_subscriptions sub
         LEFT JOIN seller_package_plans pp
           ON pp.package_id = sub.package_id
          AND pp.package_type = sub.package_type
         WHERE sub.seller_id = ?
           AND sub.status = 'active'
           AND (sub.expires_at IS NULL OR sub.expires_at > NOW())`,
        [req.sellerId]
      );

      const allowed = rows.some(
        (r) =>
          (!plans.length || plans.includes(slug(r.plan_name))) &&
          (!types.length || types.includes(r.package_type))
      );

      if (!allowed) {
        return res.status(403).json({
          success: false,
          code: "PACKAGE_REQUIRED",
          message:
            "This feature is not available in your plan, or your plan has expired. Please upgrade.",
        });
      }

      next();
    } catch (error) {
      console.error("PACKAGE GATE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to verify your package.",
      });
    }
  };
}

// ======================================================
// SELLER PASSBOOK
// GET /api/wallet/passbook
// ======================================================

router.get("/passbook", authenticateSeller, async (req, res) => {
  try {
    const sellerId = req.sellerId;
    const { from, to, search, type, category } = req.query;

    const dateError = validateDateFilters(from, to);

    if (dateError) {
      return res.status(400).json({
        success: false,
        message: dateError,
      });
    }

    const [walletRows] = await pool.query(
      `SELECT id, balance, currency, status
       FROM seller_wallet
       WHERE seller_id = ?
       ORDER BY id DESC
       LIMIT 1`,
      [sellerId]
    );

    const wallet = walletRows[0] || {
      balance: 0,
      currency: "INR",
      status: "inactive",
    };

    const conditions = ["seller_id = ?"];
    const params = [sellerId];

    if (from) {
      conditions.push("created_at >= ?");
      params.push(`${from} 00:00:00`);
    }

    if (to) {
      conditions.push("created_at < DATE_ADD(?, INTERVAL 1 DAY)");
      params.push(`${to} 00:00:00`);
    }

    if (type) {
      const normalizedType = String(type).toLowerCase();

      if (!["credit", "debit"].includes(normalizedType)) {
        return res.status(400).json({
          success: false,
          message: "Type must be credit or debit.",
        });
      }

      conditions.push("LOWER(transaction_type) = ?");
      params.push(normalizedType);
    }

    if (category && String(category).trim()) {
      conditions.push("LOWER(reference_type) = ?");
      params.push(String(category).trim().toLowerCase());
    }

    if (search && String(search).trim()) {
      const term = `%${String(search).trim()}%`;

      conditions.push(
        `(CAST(reference_id AS CHAR) LIKE ?
          OR reason LIKE ?
          OR CAST(payment_id AS CHAR) LIKE ?)`
      );

      params.push(term, term, term);
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
             WHEN LOWER(transaction_type) IN ('credit', 'cr')
              AND LOWER(status) IN ('success','successful','completed','paid')
             THEN amount ELSE 0
           END
         ), 0) AS total_credit,
         COALESCE(SUM(
           CASE
             WHEN LOWER(transaction_type) IN ('debit', 'dr')
              AND LOWER(status) IN ('success','successful','completed','paid')
             THEN amount ELSE 0
           END
         ), 0) AS total_debit
       FROM seller_transactions
       WHERE seller_id = ?`,
      [sellerId]
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

// ======================================================
// CREATE WALLET RECHARGE ORDER
// POST /api/wallet/recharge/create-order
// ======================================================

router.post(
  "/recharge/create-order",
  authenticateSeller,
  async (req, res) => {
    try {
      const amountInPaise = getRechargeAmountInPaise(
        req.body?.amount
      );

      if (!amountInPaise) {
        return res.status(400).json({
          success: false,
          message: "Recharge amount must be between ₹1 and ₹1,00,000.",
        });
      }

      const razorpay = getRazorpay();

      const order = await razorpay.orders.create({
        amount: amountInPaise,
        currency: "INR",
        receipt: `wr_${Date.now()}_${req.sellerId}`,
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
      console.error("WALLET RECHARGE ORDER ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to create recharge order.",
      });
    }
  }
);

// ======================================================
// VERIFY RECHARGE AND CREDIT WALLET
// POST /api/wallet/recharge/verify
// ======================================================

router.post(
  "/recharge/verify",
  authenticateSeller,
  async (req, res) => {
    let connection;

    try {
      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      } = req.body || {};

      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          success: false,
          message: "Payment verification details are missing.",
        });
      }

      if (
        !verifyRazorpaySignature(
          razorpay_order_id,
          razorpay_payment_id,
          razorpay_signature
        )
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

      const amount = Number((order.amount / 100).toFixed(2));

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid recharge amount.",
        });
      }

      connection = await pool.getConnection();
      await connection.beginTransaction();

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
        `SELECT id, balance_after
         FROM seller_transactions
         WHERE seller_id = ?
           AND payment_id = ?
         LIMIT 1
         FOR UPDATE`,
        [req.sellerId, razorpay_payment_id]
      );

      if (existingTransactions.length) {
        const [currentWallet] = await connection.query(
          `SELECT balance
           FROM seller_wallet
           WHERE seller_id = ?
           ORDER BY id DESC
           LIMIT 1`,
          [req.sellerId]
        );

        await connection.commit();

        return res.status(200).json({
          success: true,
          already_credited: true,
          message: "This recharge has already been credited.",
          balance: money(
            currentWallet[0]?.balance ??
            existingTransactions[0].balance_after
          ),
        });
      }

      const [walletRows] = await connection.query(
        `SELECT id, balance, currency, status
         FROM seller_wallet
         WHERE seller_id = ?
         ORDER BY id DESC
         LIMIT 1
         FOR UPDATE`,
        [req.sellerId]
      );

      let wallet = walletRows[0];

      if (!wallet) {
        const [created] = await connection.query(
          `INSERT INTO seller_wallet
           (seller_id, balance, currency, status)
           VALUES (?, 0.00, 'INR', 'active')`,
          [req.sellerId]
        );

        wallet = {
          id: created.insertId,
          balance: 0,
          currency: "INR",
          status: "active",
        };
      }

      const before = money(wallet.balance);
      const after = money(before + amount);

      await connection.query(
        `UPDATE seller_wallet
         SET balance = ?, status = 'active'
         WHERE id = ?`,
        [after, wallet.id]
      );

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
          `Wallet recharge through Razorpay. Order ID: ${razorpay_order_id}`,
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

      console.error("WALLET RECHARGE VERIFY ERROR:", error);

      return res.status(500).json({
        success: false,
        message:
          "Wallet recharge verification failed. If money was deducted, contact support before retrying.",
      });
    } finally {
      if (connection) connection.release();
    }
  }
);

// ======================================================
// ADMIN: GET ALL SELLERS AND WALLET BALANCES
// GET /api/wallet/admin/sellers
// ======================================================

router.get(
  "/admin/sellers",
  authenticateAdmin,
  async (req, res) => {
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
           ON w.id = (
             SELECT sw.id
             FROM seller_wallet sw
             WHERE sw.seller_id = s.id
             ORDER BY sw.id DESC
             LIMIT 1
           )
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
  }
);

// ======================================================
// ADMIN: ALL SELLERS PASSBOOK
// GET /api/wallet/admin/passbook
// ======================================================

router.get(
  "/admin/passbook",
  authenticateAdmin,
  async (req, res) => {
    try {
      const { from, to, search, seller_id, type } = req.query;

      const dateError = validateDateFilters(from, to);

      if (dateError) {
        return res.status(400).json({
          success: false,
          message: dateError,
        });
      }

      const conditions = ["1 = 1"];
      const params = [];

      if (from) {
        conditions.push("t.created_at >= ?");
        params.push(`${from} 00:00:00`);
      }

      if (to) {
        conditions.push(
          "t.created_at < DATE_ADD(?, INTERVAL 1 DAY)"
        );
        params.push(`${to} 00:00:00`);
      }

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

        params.push(
          term,
          term,
          term,
          term,
          term,
          term,
          term
        );
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
         FROM seller_wallet
         WHERE id IN (
           SELECT MAX(id)
           FROM seller_wallet
           GROUP BY seller_id
         )`
      );

      const [transactionSummary] = await pool.query(
        `SELECT
           COALESCE(SUM(
             CASE
               WHEN LOWER(transaction_type) IN ('credit','cr')
                AND LOWER(status) IN ('success','successful','completed','paid')
               THEN amount ELSE 0
             END
           ), 0) AS total_credit,
           COALESCE(SUM(
             CASE
               WHEN LOWER(transaction_type) IN ('debit','dr')
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
        transactions,
      });
    } catch (error) {
      console.error("ADMIN PASSBOOK API ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load admin passbook.",
      });
    }
  }
);

// ======================================================
// ADMIN: MANUAL CREDIT / DEBIT
// POST /api/wallet/admin/adjust
// ======================================================

router.post(
  "/admin/adjust",
  authenticateAdmin,
  async (req, res) => {
    let connection;

    try {
      const sellerId = Number(req.body.seller_id);
      const amount = Number(req.body.amount);
      const type = String(
        req.body.transaction_type || ""
      ).toLowerCase();
      const enteredReason = String(
        req.body.reason || ""
      ).trim();

      if (!Number.isInteger(sellerId) || sellerId <= 0) {
        return res.status(400).json({
          success: false,
          message: "Valid seller ID is required.",
        });
      }

      if (
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 100000000
      ) {
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

      if (!enteredReason || enteredReason.length > 500) {
        return res.status(400).json({
          success: false,
          message: "Please enter a reason (maximum 500 characters).",
        });
      }

      const roundedAmount = money(amount);

      if (roundedAmount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Amount must be greater than zero.",
        });
      }

      const adminId = req.admin.id || req.admin.admin_id || "admin";
      const reason =
        `${enteredReason} (Admin ID: ${adminId})`;

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

      const [walletRows] = await connection.query(
        `SELECT id, balance, currency, status
         FROM seller_wallet
         WHERE seller_id = ?
         ORDER BY id DESC
         LIMIT 1
         FOR UPDATE`,
        [sellerId]
      );

      let wallet = walletRows[0];

      if (!wallet) {
        const [created] = await connection.query(
          `INSERT INTO seller_wallet
           (seller_id, balance, currency, status)
           VALUES (?, 0.00, 'INR', 'active')`,
          [sellerId]
        );

        wallet = {
          id: created.insertId,
          balance: 0,
          currency: "INR",
          status: "active",
        };
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
          message:
            "Insufficient wallet balance. Debit cannot make balance negative.",
          current_balance: before,
        });
      }

      await connection.query(
        `UPDATE seller_wallet
         SET balance = ?, status = 'active'
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
        [
          sellerId,
          wallet.id,
          type,
          roundedAmount,
          reason,
          before,
          after,
        ]
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
          status: "success",
        },
      });
    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch (rollbackError) {
          console.error("ADMIN WALLET ROLLBACK ERROR:", rollbackError);
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
  }
);

// ======================================================
// EXPORT ROUTER
// ======================================================

module.exports = router;