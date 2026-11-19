
const express = require("express");
const router = express.Router();
const pool = require("./pool");
const crypto = require("crypto");

const PLATFORM_FEE = 10;

const VALID_STATUSES = [
  "new",
  "courier_assigned",
  "pickup_scheduled",
  "in_transit",
  "out_for_delivery",
  "delivered",
  "ndr",
  "rto_in_transit",
  "rto_delivered",
  "cancelled",
];

const VALID_ORDER_TYPES = ["forward", "reverse"];
const VALID_ZONES = ["domestic", "international"];
const VALID_PAYMENT_MODES = ["prepaid", "cod"];

const numberValue = (value, fallback = 0) => {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  return Number(value);
};

const nullableString = (value) => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  return String(value).trim() || null;
};

const generateOrderNumber = () => {
  return `DSO-${Date.now()}-${crypto
    .randomBytes(3)
    .toString("hex")
    .toUpperCase()}`;
};

// ======================================================
// SELLER AUTHENTICATION
// ======================================================

async function sellerAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : "";

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(401).json({
        success: false,
        message: "Seller login required",
      });
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const [sessions] = await pool.query(
      `SELECT seller_id
       FROM seller_login_sessions
       WHERE session_token = ?
         AND status = 'active'
         AND expires_at > NOW()
       LIMIT 1`,
      [tokenHash]
    );

    if (!sessions.length) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again.",
      });
    }

    req.sellerId = Number(sessions[0].seller_id);

    return next();
  } catch (error) {
    console.error("SELLER AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Seller authentication failed",
    });
  }
}

// ======================================================
// NORMALIZE ORDER
// ======================================================

function normalizeOrder(body) {
  const buyer = body.buyer || {};

  const paymentText = String(
    body.payment_mode ?? body.payMode ?? "prepaid"
  )
    .trim()
    .toLowerCase();

  const statusText = String(body.status || "new")
    .trim()
    .toLowerCase();

  const orderType = String(body.order_type || "forward")
    .trim()
    .toLowerCase();

  const zone = String(body.zone || "domestic")
    .trim()
    .toLowerCase();

  const isCOD =
    paymentText === "cash on delivery" ||
    paymentText === "cod";

  const invoiceAmount = numberValue(
    body.invoice_amount ?? body.amount ?? body.cod_amount
  );

  const dimensions = {
    length: numberValue(body.length),
    width: numberValue(body.width ?? body.breadth),
    height: numberValue(body.height),
    deadWeight: numberValue(
      body.dead_weight ?? body.deadWeight
    ),
  };

  const customerAddress =
    body.customer_address ??
    buyer.address ??
    [
      body.address_line1,
      body.address_line2,
      body.pincode ?? buyer.pincode,
    ]
      .filter(Boolean)
      .join(", ");

  return {
    warehouse_id: body.warehouse_id || null,

    order_no: nullableString(body.order_no ?? body.id),

    reference_id: nullableString(
      body.reference_id ?? body.ref
    ),

    order_date: body.order_date ?? body.date ?? null,

    order_type: orderType,

    zone,

    status:
      statusText === "assigned"
        ? "courier_assigned"
        : statusText,

    payment_mode: isCOD ? "cod" : paymentText,

    cod_amount: isCOD
      ? numberValue(
          body.cod_amount ??
          body.amount ??
          body.invoice_amount
        )
      : 0,

    invoice_amount: invoiceAmount,

    customer_name: String(
      body.customer_name ?? buyer.name ?? ""
    ).trim(),

    customer_phone: String(
      body.customer_phone ?? buyer.phone ?? ""
    ).trim(),

    customer_email: nullableString(
      body.customer_email ?? buyer.email
    ),

    customer_address: String(customerAddress || "").trim(),

    customer_city: nullableString(
      body.customer_city ?? buyer.city
    ),

    customer_state: nullableString(
      body.customer_state ?? buyer.state
    ),

    customer_pincode: nullableString(
      body.customer_pincode ??
      body.pincode ??
      buyer.pincode
    ),

    customer_country: String(
      body.customer_country || "India"
    ).trim(),

    dead_weight: dimensions.deadWeight,
    length: dimensions.length,
    width: dimensions.width,
    height: dimensions.height,
  };
}

// ======================================================
// VALIDATE ORDER DATE
// ======================================================

function isValidOrderDate(value) {
  if (!value) return false;

  const date = new Date(value);

  return !Number.isNaN(date.getTime());
}

// ======================================================
// GET ORDER STATISTICS
// GET /api/order/stats
// ======================================================

router.get("/stats", sellerAuth, async (req, res) => {
  try {
    const sellerId = req.sellerId;

    const [rows] = await pool.query(
      `SELECT
        COUNT(*) AS total_orders,

        COALESCE(SUM(status = 'new'), 0)
          AS new_orders,

        COALESCE(SUM(status = 'courier_assigned'), 0)
          AS courier_assigned,

        COALESCE(SUM(status = 'pickup_scheduled'), 0)
          AS pickup_scheduled,

        COALESCE(SUM(status = 'in_transit'), 0)
          AS in_transit,

        COALESCE(SUM(status = 'out_for_delivery'), 0)
          AS out_for_delivery,

        COALESCE(SUM(status = 'delivered'), 0)
          AS delivered,

        COALESCE(SUM(status = 'cancelled'), 0)
          AS cancelled,

        COALESCE(SUM(status = 'ndr'), 0)
          AS ndr,

        COALESCE(
          SUM(status IN ('rto_in_transit', 'rto_delivered')),
          0
        ) AS rto

       FROM orders
       WHERE seller_id = ?
         AND is_archived = 0`,
      [sellerId]
    );

    return res.json({
      success: true,
      stats: rows[0],
    });
  } catch (error) {
    console.error("ORDER STATS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch order statistics",
    });
  }
});

// ======================================================
// GET SELLER ORDERS
// GET /api/order
// ======================================================

router.get("/", sellerAuth, async (req, res) => {
  try {
    const sellerId = req.sellerId;

    const conditions = [
      "seller_id = ?",
      "is_archived = 0",
    ];

    const values = [sellerId];

    if (req.query.status && req.query.status !== "all") {
      const status = String(req.query.status).toLowerCase();

      const normalizedStatus =
        status === "assigned"
          ? "courier_assigned"
          : status;

      if (!VALID_STATUSES.includes(normalizedStatus)) {
        return res.status(400).json({
          success: false,
          message: "Invalid order status filter",
        });
      }

      conditions.push("status = ?");
      values.push(normalizedStatus);
    }

    if (req.query.search) {
      const search = `%${String(req.query.search).trim()}%`;

      conditions.push(
        `(order_no LIKE ?
          OR reference_id LIKE ?
          OR customer_name LIKE ?
          OR customer_phone LIKE ?)`
      );

      values.push(search, search, search, search);
    }

    const [orders] = await pool.query(
      `SELECT *
       FROM orders
       WHERE ${conditions.join(" AND ")}
       ORDER BY id DESC`,
      values
    );

    return res.json({
      success: true,
      count: orders.length,
      orders,
    });
  } catch (error) {
    console.error("FETCH ORDERS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch orders",
    });
  }
});

// ======================================================
// CREATE ORDER + ₹10 PLATFORM FEE
// POST /api/order
// ======================================================

router.post("/", sellerAuth, async (req, res) => {
  let connection;
  let transactionStarted = false;

  try {
    const sellerId = req.sellerId;

    const order = normalizeOrder(req.body || {});

    // BASIC VALIDATION

    if (
      !order.customer_name ||
      !order.customer_phone ||
      !order.customer_address
    ) {
      return res.status(400).json({
        success: false,
        message: "Customer name, phone and address are required",
      });
    }

    if (order.customer_phone.length > 15) {
      return res.status(400).json({
        success: false,
        message: "Customer phone number is too long",
      });
    }

    if (!isValidOrderDate(order.order_date)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid order date",
      });
    }

    if (!VALID_ORDER_TYPES.includes(order.order_type)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order type",
      });
    }

    if (!VALID_ZONES.includes(order.zone)) {
      return res.status(400).json({
        success: false,
        message: "Invalid zone",
      });
    }

    if (!VALID_STATUSES.includes(order.status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order status",
      });
    }

    if (!VALID_PAYMENT_MODES.includes(order.payment_mode)) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment mode",
      });
    }

    const numericFields = [
      order.cod_amount,
      order.invoice_amount,
      order.dead_weight,
      order.length,
      order.width,
      order.height,
    ];

    if (
      numericFields.some(
        (value) =>
          !Number.isFinite(value) ||
          value < 0
      )
    ) {
      return res.status(400).json({
        success: false,
        message: "Amounts, weight and dimensions must be valid",
      });
    }

    if (
      order.payment_mode === "cod" &&
      order.cod_amount <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "COD amount must be greater than zero",
      });
    }

    // CALCULATE WEIGHT

    const volumetricWeight =
      (order.length * order.width * order.height) / 5000;

    const chargeableWeight = Math.max(
      order.dead_weight,
      volumetricWeight
    );

    // GENERATE ORDER NUMBER

    const orderNo =
      order.order_no || generateOrderNumber();

    // START DATABASE TRANSACTION

    connection = await pool.getConnection();

    await connection.beginTransaction();

    transactionStarted = true;

    // CHECK DUPLICATE ORDER

    const [existingOrders] = await connection.query(
      `SELECT *
       FROM orders
       WHERE seller_id = ?
         AND order_no = ?
       LIMIT 1`,
      [sellerId, orderNo]
    );

    if (existingOrders.length) {
      await connection.rollback();
      transactionStarted = false;

      return res.json({
        success: true,
        duplicate: true,
        message: "This order already exists",
        order: existingOrders[0],
        platform_fee: 0,
      });
    }

    // LOCK SELLER WALLET

    const [wallets] = await connection.query(
      `SELECT
         id,
         seller_id,
         balance,
         currency,
         status
       FROM seller_wallet
       WHERE seller_id = ?
       ORDER BY id DESC
       LIMIT 1
       FOR UPDATE`,
      [sellerId]
    );

    if (!wallets.length) {
      await connection.rollback();
      transactionStarted = false;

      return res.status(402).json({
        success: false,
        message: "Wallet not found. Please recharge your wallet.",
      });
    }

    const wallet = wallets[0];

    if (
      wallet.status &&
      String(wallet.status).toLowerCase() !== "active"
    ) {
      await connection.rollback();
      transactionStarted = false;

      return res.status(403).json({
        success: false,
        message: "Your wallet is inactive",
      });
    }

    const balanceBefore = Number(wallet.balance || 0);

    if (
      !Number.isFinite(balanceBefore) ||
      balanceBefore < PLATFORM_FEE
    ) {
      await connection.rollback();
      transactionStarted = false;

      return res.status(402).json({
        success: false,
        message: "Insufficient wallet balance",
        required_amount: PLATFORM_FEE,
        available_balance: balanceBefore,
      });
    }

    const balanceAfter = Number(
      (balanceBefore - PLATFORM_FEE).toFixed(2)
    );

    // INSERT ORDER

    const sql = `
      INSERT INTO orders (
        seller_id,
        warehouse_id,
        order_no,
        reference_id,
        order_date,
        order_type,
        zone,
        status,
        payment_mode,
        cod_amount,
        invoice_amount,
        customer_name,
        customer_phone,
        customer_email,
        customer_address,
        customer_city,
        customer_state,
        customer_pincode,
        customer_country,
        dead_weight,
        length,
        width,
        height,
        volumetric_weight,
        chargeable_weight
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `;

    const values = [
      sellerId,
      order.warehouse_id,
      orderNo,
      order.reference_id,
      order.order_date,
      order.order_type,
      order.zone,
      order.status,
      order.payment_mode,
      order.cod_amount,
      order.invoice_amount,
      order.customer_name,
      order.customer_phone,
      order.customer_email,
      order.customer_address,
      order.customer_city,
      order.customer_state,
      order.customer_pincode,
      order.customer_country,
      order.dead_weight,
      order.length,
      order.width,
      order.height,
      volumetricWeight,
      chargeableWeight,
    ];

    const [result] = await connection.query(sql, values);

    const orderId = result.insertId;

    // DEDUCT ₹10 PLATFORM FEE

    const [walletUpdate] = await connection.query(
      `UPDATE seller_wallet
       SET balance = ?
       WHERE id = ?
         AND seller_id = ?`,
      [balanceAfter, wallet.id, sellerId]
    );

    if (walletUpdate.affectedRows !== 1) {
      throw new Error("Wallet balance update failed");
    }

    // INSERT PLATFORM CHARGE IN PASSBOOK

    await connection.query(
      `INSERT INTO seller_transactions (
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
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        sellerId,
        wallet.id,
        "debit",
        PLATFORM_FEE,
        "Dropshy platform fee (₹10 per shipping order)",
        "platform_charge",
        orderId,
        null,
        balanceBefore,
        balanceAfter,
        "success",
      ]
    );

    // FETCH CREATED ORDER

    const [rows] = await connection.query(
      `SELECT *
       FROM orders
       WHERE id = ?
         AND seller_id = ?
       LIMIT 1`,
      [orderId, sellerId]
    );

    if (!rows.length) {
      throw new Error("Created order could not be fetched");
    }

    // COMMIT TRANSACTION

    await connection.commit();
    transactionStarted = false;

    return res.status(201).json({
      success: true,
      message: "Order created successfully",

      order: rows[0],

      charges: {
        platform_fee: PLATFORM_FEE,
        courier_charge: 0,
      },

      wallet: {
        balance_before: balanceBefore,
        balance_after: balanceAfter,
      },
    });
  } catch (error) {
    if (connection && transactionStarted) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("ORDER ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("CREATE ORDER ERROR:", error);

    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        success: false,
        message: "Duplicate order number. Please try again.",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Unable to create order",
      error: error.message,
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

module.exports = router;
