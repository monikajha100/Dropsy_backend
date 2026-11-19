
const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const pool = require("./pool");

const JWT_SECRET =
  process.env.JWT_SECRET || "DROPSHY_ADMIN_SECRET_2026";

// ======================================================
// ADMIN AUTHENTICATION
// ======================================================

function verifyAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Admin token required",
      });
    }

    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (String(decoded.role || "").toLowerCase() !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required",
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired admin token",
    });
  }
}

// ======================================================
// ADD VENDOR
// POST /api/vendors
// Vendor code is generated using inserted database ID
// ======================================================

router.post("/", verifyAdmin, async (req, res) => {
  let connection;

  try {
    const {
      vendor_name,
      contact_person,
      mobile,
      alternate_mobile,
      email,
      gst_number,
      whatsapp,
      address,
      city,
      state,
      pincode,
    } = req.body || {};

    const name = String(vendor_name || "").trim();
    const phone = String(mobile || "").trim();
    const emailValue = String(email || "").trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Vendor name is required",
      });
    }

    if (!/^[0-9]{10,15}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: "Valid mobile number is required",
      });
    }

    if (
      emailValue &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailValue)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid email address",
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Temporary code, replaced after insert
    const [result] = await connection.execute(
      `INSERT INTO vendors (
        vendor_code,
        vendor_name,
        contact_person,
        mobile,
        alternate_mobile,
        email,
        gst_number,
        whatsapp,
        address,
        city,
        state,
        pincode,
        status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
      [
        "TEMP",
        name,
        contact_person || null,
        phone,
        alternate_mobile || null,
        emailValue || null,
        gst_number || null,
        whatsapp || null,
        address || null,
        city || null,
        state || null,
        pincode || null,
      ]
    );

    const vendorCode = `VEN${String(result.insertId).padStart(5, "0")}`;

    await connection.execute(
      "UPDATE vendors SET vendor_code = ? WHERE id = ?",
      [vendorCode, result.insertId]
    );

    const [vendorRows] = await connection.execute(
      "SELECT * FROM vendors WHERE id = ? LIMIT 1",
      [result.insertId]
    );

    await connection.commit();

    return res.status(201).json({
      success: true,
      message: "Vendor added successfully",
      vendor: vendorRows[0],
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (_) {}
    }

    console.error("ADD VENDOR ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Vendor add nahi ho saka",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// GET ALL VENDORS
// GET /api/vendors
// ======================================================

router.get("/", verifyAdmin, async (req, res) => {
  try {
    const { search, status } = req.query;

    let sql = "SELECT * FROM vendors WHERE 1=1";
    const params = [];

    if (search && String(search).trim()) {
      const value = `%${String(search).trim()}%`;

      sql += ` AND (
        vendor_code LIKE ?
        OR vendor_name LIKE ?
        OR contact_person LIKE ?
        OR mobile LIKE ?
        OR email LIKE ?
      )`;

      params.push(value, value, value, value, value);
    }

    if (status && ["active", "inactive"].includes(status)) {
      sql += " AND status = ?";
      params.push(status);
    }

    sql += " ORDER BY id DESC";

    const [vendors] = await pool.query(sql, params);

    return res.status(200).json({
      success: true,
      count: vendors.length,
      vendors,
    });
  } catch (error) {
    console.error("FETCH VENDORS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Vendor list fetch nahi ho saki",
    });
  }
});

// ======================================================
// GET SINGLE VENDOR
// GET /api/vendors/:id
// ======================================================

router.get("/:id", verifyAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid vendor ID",
      });
    }

    const [rows] = await pool.execute(
      "SELECT * FROM vendors WHERE id = ? LIMIT 1",
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Vendor not found",
      });
    }

    return res.status(200).json({
      success: true,
      vendor: rows[0],
    });
  } catch (error) {
    console.error("FETCH VENDOR ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Vendor details fetch nahi ho sake",
    });
  }
});

// ======================================================
// UPDATE VENDOR
// PUT /api/vendors/:id
// ======================================================

router.put("/:id", verifyAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid vendor ID",
      });
    }

    const {
      vendor_name,
      contact_person,
      mobile,
      alternate_mobile,
      email,
      gst_number,
      whatsapp,
      address,
      city,
      state,
      pincode,
    } = req.body || {};

    const name = String(vendor_name || "").trim();
    const phone = String(mobile || "").trim();
    const emailValue = String(email || "").trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Vendor name is required",
      });
    }

    if (!/^[0-9]{10,15}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: "Valid mobile number is required",
      });
    }

    if (
      emailValue &&
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailValue)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid email address",
      });
    }

    // Check vendor existence first
    const [existing] = await pool.execute(
      "SELECT id FROM vendors WHERE id = ? LIMIT 1",
      [id]
    );

    if (!existing.length) {
      return res.status(404).json({
        success: false,
        message: "Vendor not found",
      });
    }

    await pool.execute(
      `UPDATE vendors SET
        vendor_name = ?,
        contact_person = ?,
        mobile = ?,
        alternate_mobile = ?,
        email = ?,
        gst_number = ?,
        whatsapp = ?,
        address = ?,
        city = ?,
        state = ?,
        pincode = ?
       WHERE id = ?`,
      [
        name,
        contact_person || null,
        phone,
        alternate_mobile || null,
        emailValue || null,
        gst_number || null,
        whatsapp || null,
        address || null,
        city || null,
        state || null,
        pincode || null,
        id,
      ]
    );

    const [updated] = await pool.execute(
      "SELECT * FROM vendors WHERE id = ? LIMIT 1",
      [id]
    );

    return res.status(200).json({
      success: true,
      message: "Vendor updated successfully",
      vendor: updated[0],
    });
  } catch (error) {
    console.error("UPDATE VENDOR ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Vendor update nahi ho saka",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  }
});

// ======================================================
// UPDATE VENDOR STATUS
// PATCH /api/vendors/:id/status
// ======================================================

router.patch("/:id/status", verifyAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const status = String(req.body?.status || "").toLowerCase();

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid vendor ID",
      });
    }

    if (!["active", "inactive"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be active or inactive",
      });
    }

    const [existing] = await pool.execute(
      "SELECT id FROM vendors WHERE id = ? LIMIT 1",
      [id]
    );

    if (!existing.length) {
      return res.status(404).json({
        success: false,
        message: "Vendor not found",
      });
    }

    await pool.execute(
      "UPDATE vendors SET status = ? WHERE id = ?",
      [status, id]
    );

    return res.status(200).json({
      success: true,
      message: `Vendor ${status} successfully`,
      status,
    });
  } catch (error) {
    console.error("VENDOR STATUS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Vendor status update nahi ho saka",
    });
  }
});

module.exports = router;
