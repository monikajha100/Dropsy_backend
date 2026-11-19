
const express = require("express");
const router = express.Router();
const pool = require("./pool");
const crypto = require("crypto");

// ======================================================
// ROUTER TEST
// GET /api/seller-warehouses/test
// ======================================================

router.get("/test", (req, res) => {
  return res.status(200).json({
    success: true,
    status: true,
    message: "Seller Warehouse Router Connected Successfully",
  });
});

// ======================================================
// SELLER AUTHENTICATION
// ======================================================

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) return null;

  const token = match[1].trim();

  if (!token || token.length > 500) return null;

  return token;
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

async function authenticateSeller(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        status: false,
        message: "Seller login token missing.",
      });
    }

    const tokenHash = hashSessionToken(token);

    const [sessions] = await pool.query(
      `SELECT id, seller_id
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
        status: false,
        message: "Invalid or expired seller session. Please login again.",
      });
    }

    req.sellerId = sessions[0].seller_id;
    req.sessionId = sessions[0].id;

    return next();

  } catch (error) {
    console.error("WAREHOUSE AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to verify seller session.",
    });
  }
}

// ======================================================
// HELPERS
// ======================================================

const clean = (value) =>
  typeof value === "string" ? value.trim() : "";

const toBoolean = (value) =>
  value === true ||
  value === 1 ||
  value === "1" ||
  value === "true";

function validateWarehouse(data) {
  const errors = {};

  if (!data.warehouse_name) {
    errors.warehouse_name = "Warehouse name is required.";
  }

  if (!data.contact_person) {
    errors.contact_person = "Contact person is required.";
  }

  if (!/^[6-9]\d{9}$/.test(data.phone)) {
    errors.phone = "Valid 10 digit mobile number required.";
  }

  if (
    data.alternate_phone &&
    !/^[6-9]\d{9}$/.test(data.alternate_phone)
  ) {
    errors.alternate_phone = "Invalid alternate mobile number.";
  }

  if (
    data.email &&
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)
  ) {
    errors.email = "Invalid email address.";
  }

  if (!data.address_line1) {
    errors.address_line1 = "Pickup address is required.";
  }

  if (!/^\d{6}$/.test(data.pincode)) {
    errors.pincode = "Valid 6 digit pincode required.";
  }

  if (!data.city) {
    errors.city = "City is required.";
  }

  if (!data.state) {
    errors.state = "State is required.";
  }

  if (!data.return_same) {
    if (!data.return_address_line1) {
      errors.return_address_line1 = "Return address is required.";
    }

    if (!/^\d{6}$/.test(data.return_pincode)) {
      errors.return_pincode = "Valid return pincode required.";
    }

    if (!data.return_city) {
      errors.return_city = "Return city is required.";
    }

    if (!data.return_state) {
      errors.return_state = "Return state is required.";
    }
  }

  if (!["active", "inactive"].includes(data.status)) {
    errors.status = "Invalid warehouse status.";
  }

  return errors;
}

function prepareWarehouse(body = {}) {
  const returnSame = toBoolean(body.return_same);

  const data = {
    warehouse_name: clean(body.warehouse_name),
    contact_person: clean(body.contact_person),
    phone: clean(body.phone).replace(/\D/g, ""),
    alternate_phone: clean(body.alternate_phone).replace(/\D/g, ""),
    email: clean(body.email).toLowerCase(),

    address_line1: clean(body.address_line1),
    address_line2: clean(body.address_line2),
    landmark: clean(body.landmark),
    pincode: clean(body.pincode).replace(/\D/g, ""),
    city: clean(body.city),
    state: clean(body.state),

    return_same: returnSame ? 1 : 0,

    return_address_line1: returnSame
      ? clean(body.address_line1)
      : clean(body.return_address_line1),

    return_address_line2: returnSame
      ? clean(body.address_line2)
      : clean(body.return_address_line2),

    return_pincode: returnSame
      ? clean(body.pincode)
      : clean(body.return_pincode).replace(/\D/g, ""),

    return_city: returnSame
      ? clean(body.city)
      : clean(body.return_city),

    return_state: returnSame
      ? clean(body.state)
      : clean(body.return_state),

    is_default: toBoolean(body.is_default) ? 1 : 0,
    status: clean(body.status || "active").toLowerCase(),
  };

  if (!data.alternate_phone) data.alternate_phone = null;
  if (!data.email) data.email = null;
  if (!data.address_line2) data.address_line2 = null;
  if (!data.landmark) data.landmark = null;
  if (!data.return_address_line2) data.return_address_line2 = null;

  return data;
}

const WAREHOUSE_COLUMNS = [
  "warehouse_name",
  "contact_person",
  "phone",
  "alternate_phone",
  "email",
  "address_line1",
  "address_line2",
  "landmark",
  "pincode",
  "city",
  "state",
  "return_same",
  "return_address_line1",
  "return_address_line2",
  "return_pincode",
  "return_city",
  "return_state",
  "is_default",
  "status",
];

function warehouseValues(data) {
  return WAREHOUSE_COLUMNS.map((column) => data[column]);
}

// ======================================================
// GET ALL WAREHOUSES
// GET /api/seller-warehouses
// ======================================================

router.get("/", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT *
       FROM seller_warehouses
       WHERE seller_id = ?
       ORDER BY is_default DESC, id DESC`,
      [req.sellerId]
    );

    return res.json({
      success: true,
      status: true,
      count: rows.length,
      warehouses: rows,
    });

  } catch (error) {
    console.error("FETCH WAREHOUSES ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to fetch warehouses.",
      error: error.message,
    });
  }
});

// ======================================================
// GET SINGLE WAREHOUSE
// ======================================================

router.get("/:id", authenticateSeller, async (req, res) => {
  try {
    const warehouseId = Number(req.params.id);

    if (!Number.isInteger(warehouseId) || warehouseId <= 0) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Invalid warehouse ID.",
      });
    }

    const [rows] = await pool.query(
      `SELECT *
       FROM seller_warehouses
       WHERE id = ? AND seller_id = ?
       LIMIT 1`,
      [warehouseId, req.sellerId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        status: false,
        message: "Warehouse not found.",
      });
    }

    return res.json({
      success: true,
      status: true,
      warehouse: rows[0],
    });

  } catch (error) {
    console.error("FETCH SINGLE WAREHOUSE ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to fetch warehouse.",
    });
  }
});

// ======================================================
// ADD WAREHOUSE
// ======================================================

router.post("/", authenticateSeller, async (req, res) => {
  let connection;

  try {
    const data = prepareWarehouse(req.body);
    const errors = validateWarehouse(data);

    if (Object.keys(errors).length) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Please correct warehouse details.",
        errors,
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [seller] = await connection.query(
      `SELECT id
       FROM sellers
       WHERE id = ?
       LIMIT 1
       FOR UPDATE`,
      [req.sellerId]
    );

    if (!seller.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        status: false,
        message: "Seller not found.",
      });
    }

    if (data.is_default) {
      await connection.query(
        `UPDATE seller_warehouses
         SET is_default = 0
         WHERE seller_id = ?`,
        [req.sellerId]
      );
    }

    const columns = ["seller_id", ...WAREHOUSE_COLUMNS];
    const placeholders = columns.map(() => "?").join(", ");

    const [result] = await connection.query(
      `INSERT INTO seller_warehouses
       (${columns.map((column) => `\`${column}\``).join(", ")})
       VALUES (${placeholders})`,
      [req.sellerId, ...warehouseValues(data)]
    );

    await connection.commit();

    const [created] = await pool.query(
      `SELECT *
       FROM seller_warehouses
       WHERE id = ? AND seller_id = ?
       LIMIT 1`,
      [result.insertId, req.sellerId]
    );

    return res.status(201).json({
      success: true,
      status: true,
      message: "Warehouse added successfully.",
      warehouse: created[0],
    });

  } catch (error) {
    if (connection) await connection.rollback();

    console.error("ADD WAREHOUSE ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to add warehouse.",
      error: error.message,
    });

  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// UPDATE WAREHOUSE
// ======================================================

router.put("/:id", authenticateSeller, async (req, res) => {
  let connection;

  try {
    const warehouseId = Number(req.params.id);

    if (!Number.isInteger(warehouseId) || warehouseId <= 0) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Invalid warehouse ID.",
      });
    }

    const data = prepareWarehouse(req.body);
    const errors = validateWarehouse(data);

    if (Object.keys(errors).length) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Please correct warehouse details.",
        errors,
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    await connection.query(
      `SELECT id
       FROM sellers
       WHERE id = ?
       LIMIT 1
       FOR UPDATE`,
      [req.sellerId]
    );

    const [existing] = await connection.query(
      `SELECT id
       FROM seller_warehouses
       WHERE id = ? AND seller_id = ?
       LIMIT 1
       FOR UPDATE`,
      [warehouseId, req.sellerId]
    );

    if (!existing.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        status: false,
        message: "Warehouse not found.",
      });
    }

    if (data.is_default) {
      await connection.query(
        `UPDATE seller_warehouses
         SET is_default = 0
         WHERE seller_id = ?`,
        [req.sellerId]
      );
    }

    const setClause = WAREHOUSE_COLUMNS
      .map((column) => `\`${column}\` = ?`)
      .join(", ");

    await connection.query(
      `UPDATE seller_warehouses
       SET ${setClause}
       WHERE id = ? AND seller_id = ?`,
      [...warehouseValues(data), warehouseId, req.sellerId]
    );

    await connection.commit();

    const [updated] = await pool.query(
      `SELECT *
       FROM seller_warehouses
       WHERE id = ? AND seller_id = ?
       LIMIT 1`,
      [warehouseId, req.sellerId]
    );

    return res.json({
      success: true,
      status: true,
      message: "Warehouse updated successfully.",
      warehouse: updated[0],
    });

  } catch (error) {
    if (connection) await connection.rollback();

    console.error("UPDATE WAREHOUSE ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to update warehouse.",
      error: error.message,
    });

  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// DELETE WAREHOUSE
// ======================================================

router.delete("/:id", authenticateSeller, async (req, res) => {
  try {
    const warehouseId = Number(req.params.id);

    if (!Number.isInteger(warehouseId) || warehouseId <= 0) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Invalid warehouse ID.",
      });
    }

    const [result] = await pool.query(
      `DELETE FROM seller_warehouses
       WHERE id = ? AND seller_id = ?`,
      [warehouseId, req.sellerId]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        status: false,
        message: "Warehouse not found.",
      });
    }

    return res.json({
      success: true,
      status: true,
      message: "Warehouse deleted successfully.",
      warehouseId,
    });

  } catch (error) {
    console.error("DELETE WAREHOUSE ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to delete warehouse.",
      error: error.message,
    });
  }
});

module.exports = router;
