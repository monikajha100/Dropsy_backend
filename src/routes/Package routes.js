// =====================================================
// package-routes.js  (COMPLETE FILE)
//
// Seller: my-package, quotes, purchase-with-wallet
// Admin : seller-packages list + detail
//
// Mount (server file mein):
//   const packageRoutes = require("./package-routes");
//   app.use("/api/payment", packageRoutes);
//
// NOTE: Agar purane payment router mein already "/my-package" hai,
// to ya use hata do, ya is router ko usse PEHLE mount karo,
// warna purana wala hi chalega.
//
// ASSUMPTIONS (apne asli naam se badal lena):
//  - table seller_packages: id, seller_id, package_type, plan_key,
//    package_name, amount_paid, status ('active'|'upgraded'|'expired'),
//    starts_at, expires_at
//  - sellers.registration_amount = registration ke time liya gaya plan amount
//  - seller_wallet / seller_transactions wahi hain jo wallet file mein hain
// =====================================================

const express = require("express");
const router = express.Router();
const pool = require("./pool");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

// =====================================================
// CONFIG
// =====================================================

const PACKAGE_DURATION_DAYS = 365; // <-- apna duration set karein

// Server-side price (GST ke saath). Frontend ke paymentTotal jaisi hi.
const PLAN_PRICES = {
  national: { basic: 5900, advance: 23600, royal: 73599 },
  international: { basic: 9438, advance: 47160, royal: 97190 },
  website: { basic: 9322, advance: 14042, royal: 19942 },
};

const PLAN_NAMES = { basic: "Basic", advance: "Advance", royal: "Royal" };
const PLAN_RANK = { basic: 1, advance: 2, royal: 3 };

const TYPE_TITLES = {
  national: "National E-commerce",
  international: "International Dropshipping",
  website: "Website Dropshipping",
};

// Registration ke time liya gaya plan. Naam apne hisaab se badlo.
const REG_PLAN_NAMES = {
  5999: "Registration Plan - ₹5,999",
  11800: "Registration Plan - ₹11,800",
};

function money(value) {
  return Number(Number(value || 0).toFixed(2));
}

// =====================================================
// AUTH
// =====================================================

async function authenticateSeller(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);

    if (!match) {
      return res.status(401).json({ success: false, message: "Please log in first." });
    }

    const tokenHash = crypto.createHash("sha256").update(match[1]).digest("hex");

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
      return res.status(401).json({ success: false, message: "Session expired. Please log in again." });
    }

    req.sellerId = sessions[0].seller_id;
    next();
  } catch (error) {
    console.error("PACKAGE SELLER AUTH ERROR:", error);
    return res.status(500).json({ success: false, message: "Unable to verify seller session." });
  }
}

function authenticateAdmin(req, res, next) {
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({ success: false, message: "Admin JWT secret is not configured." });
    }

    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Admin token required." });
    }

    const decoded = jwt.verify(header.slice(7), JWT_SECRET);

    if (String(decoded.role || "").toLowerCase() !== "admin") {
      return res.status(403).json({ success: false, message: "Admin access required." });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid or expired admin token." });
  }
}

// =====================================================
// HELPERS
// =====================================================

// state: current | lower | upgrade | buy
function buildQuote(type, planKey, activePackage) {
  const price = money(PLAN_PRICES[type][planKey]);

  let state = "buy";
  let charge = price;

  if (activePackage) {
    const currentRank = PLAN_RANK[activePackage.plan_key] || 0;
    const targetRank = PLAN_RANK[planKey];

    if (targetRank === currentRank) {
      state = "current";
      charge = 0;
    } else if (targetRank < currentRank) {
      state = "lower";
      charge = 0;
    } else {
      // Upgrade: purane plan mein jo paisa diya tha wo minus
      state = "upgrade";
      charge = money(Math.max(price - money(activePackage.amount_paid), 0));
    }
  }

  return { plan_key: planKey, price, state, charge };
}

async function getActivePackage(db, sellerId, type, forUpdate = false) {
  const [rows] = await db.query(
    `SELECT id, plan_key, package_name, amount_paid, expires_at
     FROM seller_packages
     WHERE seller_id = ?
       AND package_type = ?
       AND status = 'active'
       AND expires_at > NOW()
     ORDER BY id DESC
     LIMIT 1
     ${forUpdate ? "FOR UPDATE" : ""}`,
    [sellerId, type]
  );
  return rows[0] || null;
}

// =====================================================
// SELLER: MY PACKAGE
// GET /api/payment/my-package
// Active package mile to wo, nahi to registration plan, nahi to null
// =====================================================

router.get("/my-package", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, package_type, plan_key, package_name, amount_paid,
              status, starts_at, expires_at
       FROM seller_packages
       WHERE seller_id = ?
         AND status = 'active'
         AND expires_at > NOW()
       ORDER BY id DESC
       LIMIT 1`,
      [req.sellerId]
    );

    if (rows.length) {
      const p = rows[0];

      return res.json({
        success: true,
        package: {
          id: p.id,
          package_name: p.package_name,
          package_type: p.package_type,
          plan_name: PLAN_NAMES[p.plan_key] || p.plan_key,
          plan_key: p.plan_key,
          status: p.status,
          amount_paid: money(p.amount_paid),
          starts_at: p.starts_at,
          expires_at: p.expires_at,
        },
      });
    }

    // Fallback: registration ke time liya gaya plan
    const [sellerRows] = await pool.query(
      `SELECT registration_amount, created_at
       FROM sellers
       WHERE id = ?
       LIMIT 1`,
      [req.sellerId]
    );

    const amount = Math.round(Number(sellerRows[0]?.registration_amount || 0));

    if (REG_PLAN_NAMES[amount]) {
      return res.json({
        success: true,
        package: {
          package_name: REG_PLAN_NAMES[amount],
          package_type: "registration",
          plan_name: REG_PLAN_NAMES[amount],
          plan_key: null,
          status: "active",
          amount_paid: amount,
          starts_at: sellerRows[0].created_at,
          expires_at: null,
        },
      });
    }

    return res.json({ success: true, package: null });
  } catch (error) {
    console.error("MY PACKAGE ERROR:", error);
    return res.status(500).json({ success: false, message: "Unable to load your package." });
  }
});

// =====================================================
// SELLER: QUOTES
// GET /api/payment/package/quotes?type=national
// =====================================================

router.get("/package/quotes", authenticateSeller, async (req, res) => {
  try {
    const type = String(req.query.type || "").toLowerCase();

    if (!PLAN_PRICES[type]) {
      return res.status(400).json({ success: false, message: "Invalid package type." });
    }

    const [walletRows] = await pool.query(
      `SELECT balance FROM seller_wallet WHERE seller_id = ? LIMIT 1`,
      [req.sellerId]
    );
    const balance = money(walletRows[0]?.balance || 0);

    const active = await getActivePackage(pool, req.sellerId, type);

    const quotes = Object.keys(PLAN_PRICES[type]).map((planKey) => {
      const q = buildQuote(type, planKey, active);
      const payable = q.state === "buy" || q.state === "upgrade";

      return {
        ...q,
        shortfall: payable ? money(Math.max(q.charge - balance, 0)) : 0,
      };
    });

    return res.json({ success: true, balance, quotes });
  } catch (error) {
    console.error("PACKAGE QUOTES ERROR:", error);
    return res.status(500).json({ success: false, message: "Unable to load plan prices." });
  }
});

// =====================================================
// SELLER: PURCHASE / UPGRADE WITH WALLET
// POST /api/payment/package/purchase-with-wallet
// body: { type, planId }
// =====================================================

router.post("/package/purchase-with-wallet", authenticateSeller, async (req, res) => {
  let connection;

  try {
    const type = String(req.body?.type || "").toLowerCase();
    const planKey = String(req.body?.planId || "").toLowerCase();

    if (!PLAN_PRICES[type] || !PLAN_PRICES[type][planKey]) {
      return res.status(400).json({ success: false, message: "Invalid plan selected." });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Seller row lock: double click se do baar paisa nahi katega
    const [sellerRows] = await connection.query(
      `SELECT id FROM sellers WHERE id = ? LIMIT 1 FOR UPDATE`,
      [req.sellerId]
    );

    if (!sellerRows.length) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: "Seller account not found." });
    }

    const active = await getActivePackage(connection, req.sellerId, type, true);
    const quote = buildQuote(type, planKey, active);

    if (quote.state === "current") {
      await connection.rollback();
      return res.status(400).json({ success: false, message: "Ye plan pehle se active hai." });
    }

    if (quote.state === "lower") {
      await connection.rollback();
      return res.status(400).json({ success: false, message: "Lower plan par downgrade nahi ho sakta." });
    }

    const [walletRows] = await connection.query(
      `SELECT id, balance, status
       FROM seller_wallet
       WHERE seller_id = ?
       LIMIT 1
       FOR UPDATE`,
      [req.sellerId]
    );

    const wallet = walletRows[0];

    if (!wallet) {
      await connection.rollback();
      return res.status(400).json({ success: false, message: "Wallet empty hai. Pehle wallet recharge karein." });
    }

    if (wallet.status === "blocked") {
      await connection.rollback();
      return res.status(403).json({ success: false, message: "Aapka wallet blocked hai. Support se contact karein." });
    }

    const before = money(wallet.balance);

    if (before < quote.charge) {
      await connection.rollback();
      return res.status(400).json({
        success: false,
        message: `Wallet balance kam hai. ₹${money(quote.charge - before)} aur chahiye.`,
        shortfall: money(quote.charge - before),
      });
    }

    const after = money(before - quote.charge);
    const packageName = `${TYPE_TITLES[type]} - ${PLAN_NAMES[planKey]}`;

    // 1) Wallet se paisa kato
    await connection.query(`UPDATE seller_wallet SET balance = ? WHERE id = ?`, [after, wallet.id]);

    // 2) Purana plan band karo (upgrade case)
    if (active) {
      await connection.query(`UPDATE seller_packages SET status = 'upgraded' WHERE id = ?`, [active.id]);
    }

    // 3) Naya plan activate karo
    // amount_paid = full plan price, taaki aage ka upgrade sahi calculate ho
    const [pkgInsert] = await connection.query(
      `INSERT INTO seller_packages
        (seller_id, package_type, plan_key, package_name, amount_paid, status, starts_at, expires_at)
       VALUES (?, ?, ?, ?, ?, 'active', NOW(), DATE_ADD(NOW(), INTERVAL ? DAY))`,
      [req.sellerId, type, planKey, packageName, quote.price, PACKAGE_DURATION_DAYS]
    );

    // 4) Passbook entry
    await connection.query(
      `INSERT INTO seller_transactions
        (seller_id, wallet_id, transaction_type, amount, reason,
         reference_type, reference_id, payment_id,
         balance_before, balance_after, status)
       VALUES (?, ?, 'debit', ?, ?, 'package_plan', ?, NULL, ?, ?, 'success')`,
      [
        req.sellerId,
        wallet.id,
        quote.charge,
        `${quote.state === "upgrade" ? "Package upgrade" : "Package purchase"}: ${packageName}`,
        pkgInsert.insertId,
        before,
        after,
      ]
    );

    await connection.commit();

    return res.status(200).json({
      success: true,
      message: `${PLAN_NAMES[planKey]} package activate ho gaya!`,
      amount: quote.charge,
      balance_before: before,
      balance_after: after,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("PACKAGE ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("PACKAGE PURCHASE ERROR:", error);
    return res.status(500).json({ success: false, message: "Package activate nahi ho paya." });
  } finally {
    if (connection) connection.release();
  }
});

// =====================================================
// ADMIN: ALL SELLERS + THEIR PLAN
// GET /api/payment/admin/seller-packages
// query (optional): search, package_type, plan_key, taken=yes|no
// =====================================================

router.get("/admin/seller-packages", authenticateAdmin, async (req, res) => {
  try {
    const { search, package_type, plan_key, taken } = req.query;

    const conditions = ["1 = 1"];
    const params = [];

    if (package_type) {
      if (!["national", "international", "website"].includes(package_type)) {
        return res.status(400).json({ success: false, message: "Invalid package type." });
      }
      conditions.push("sp.package_type = ?");
      params.push(package_type);
    }

    if (plan_key) {
      if (!["basic", "advance", "royal"].includes(plan_key)) {
        return res.status(400).json({ success: false, message: "Invalid plan." });
      }
      conditions.push("sp.plan_key = ?");
      params.push(plan_key);
    }

    if (taken === "yes") conditions.push("sp.id IS NOT NULL");
    if (taken === "no") conditions.push("sp.id IS NULL");

    if (search && String(search).trim()) {
      const term = `%${String(search).trim()}%`;
      conditions.push("(s.fullName LIKE ? OR s.email LIKE ? OR s.enrollmentNumber LIKE ?)");
      params.push(term, term, term);
    }

    // Ek seller ke 2 active package ho sakte hain (alag type): 1 row per package.
    // Jis seller ka koi package nahi, uski row mein sp.* NULL aayega.
    const [rows] = await pool.query(
      `SELECT
         s.id AS seller_id,
         s.fullName AS seller_name,
         s.email,
         s.enrollmentNumber,
         s.registration_amount,
         sp.id AS package_row_id,
         sp.package_type,
         sp.plan_key,
         sp.package_name,
         sp.amount_paid,
         sp.starts_at,
         sp.expires_at
       FROM sellers s
       LEFT JOIN seller_packages sp
         ON sp.seller_id = s.id
        AND sp.status = 'active'
        AND sp.expires_at > NOW()
       WHERE ${conditions.join(" AND ")}
       ORDER BY s.id DESC, sp.id DESC
       LIMIT 1000`,
      params
    );

    const sellers = rows.map((r) => {
      const regAmount = Math.round(Number(r.registration_amount || 0));
      const hasPackage = Boolean(r.package_row_id);

      let plan_status = "none"; // package | registration | none
      let plan_name = null;

      if (hasPackage) {
        plan_status = "package";
        plan_name = r.package_name;
      } else if (REG_PLAN_NAMES[regAmount]) {
        plan_status = "registration";
        plan_name = REG_PLAN_NAMES[regAmount];
      }

      return {
        seller_id: r.seller_id,
        seller_name: r.seller_name,
        email: r.email,
        enrollmentNumber: r.enrollmentNumber,
        plan_status,
        plan_name,
        package_type: r.package_type || (plan_status === "registration" ? "registration" : null),
        plan_key: r.plan_key || null,
        amount_paid: hasPackage ? money(r.amount_paid) : plan_status === "registration" ? regAmount : 0,
        starts_at: r.starts_at,
        expires_at: r.expires_at,
      };
    });

    const summary = {
      total_sellers: new Set(sellers.map((s) => s.seller_id)).size,
      with_package: sellers.filter((s) => s.plan_status === "package").length,
      registration_only: sellers.filter((s) => s.plan_status === "registration").length,
      no_plan: sellers.filter((s) => s.plan_status === "none").length,
    };

    return res.json({ success: true, summary, count: sellers.length, sellers });
  } catch (error) {
    console.error("ADMIN SELLER PACKAGES ERROR:", error);
    return res.status(500).json({ success: false, message: "Unable to load seller packages." });
  }
});

// =====================================================
// ADMIN: ONE SELLER'S PACKAGE HISTORY
// GET /api/payment/admin/seller-packages/:sellerId
// =====================================================

router.get("/admin/seller-packages/:sellerId", authenticateAdmin, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.sellerId)) {
      return res.status(400).json({ success: false, message: "Invalid seller ID." });
    }

    const sellerId = Number(req.params.sellerId);

    const [sellerRows] = await pool.query(
      `SELECT id, fullName, email, enrollmentNumber, registration_amount
       FROM sellers
       WHERE id = ?
       LIMIT 1`,
      [sellerId]
    );

    if (!sellerRows.length) {
      return res.status(404).json({ success: false, message: "Seller not found." });
    }

    const [history] = await pool.query(
      `SELECT id, package_type, plan_key, package_name, amount_paid,
              status, starts_at, expires_at
       FROM seller_packages
       WHERE seller_id = ?
       ORDER BY id DESC`,
      [sellerId]
    );

    const [payments] = await pool.query(
      `SELECT id, amount, reason, balance_before, balance_after, created_at
       FROM seller_transactions
       WHERE seller_id = ? AND reference_type = 'package_plan'
       ORDER BY created_at DESC, id DESC`,
      [sellerId]
    );

    const regAmount = Math.round(Number(sellerRows[0].registration_amount || 0));

    return res.json({
      success: true,
      seller: sellerRows[0],
      registration_plan: REG_PLAN_NAMES[regAmount] || null,
      history,
      payments,
    });
  } catch (error) {
    console.error("ADMIN SELLER PACKAGE DETAIL ERROR:", error);
    return res.status(500).json({ success: false, message: "Unable to load seller package detail." });
  }
});

module.exports = router;