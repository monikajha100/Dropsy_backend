const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const pool = require("./pool");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

const JWT_SECRET =
  process.env.JWT_SECRET || "DROPSHY_ADMIN_SECRET_2026";

// ======================================================
// ADMIN TOKEN MIDDLEWARE
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
    console.error("ADMIN AUTH ERROR:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired admin token",
    });
  }
}

// ======================================================
// ADMIN LOGIN
// POST /admin/chk_admin_login
// ======================================================

router.post("/chk_admin_login", async (req, res) => {
  try {
    const body = req.body || {};

    const id = String(
      body.id || body.email || body.mobile || body.adminId || ""
    ).trim();

    const password = String(body.password || "");

    if (!id || !password) {
      return res.status(400).json({
        data: [],
        message: "Email/Mobile and Password are required",
        status: false,
      });
    }

    const [result] = await pool.execute(
      `SELECT id, name, email, mobile, password, status
       FROM dropshy_admin
       WHERE (email = ? OR mobile = ?) AND status = 1
       LIMIT 1`,
      [id, id]
    );

    if (!result.length) {
      return res.status(401).json({
        data: [],
        message: "Invalid Admin ID / Password",
        status: false,
      });
    }

    const admin = result[0];

    // Existing plain-text password comparison retained.
    if (String(admin.password) !== password) {
      return res.status(401).json({
        data: [],
        message: "Invalid Admin ID / Password",
        status: false,
      });
    }

    const data = {
      id: admin.id,
      name: admin.name,
      email: admin.email,
      mobile: admin.mobile,
      status: admin.status,
    };

    const token = jwt.sign(
      {
        id: admin.id,
        email: admin.email,
        role: "admin",
      },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.status(200).json({
      data,
      token,
      message: "Login Successful",
      status: true,
    });
  } catch (error) {
    console.error("ADMIN LOGIN ERROR:", error);

    return res.status(500).json({
      data: [],
      message: "Admin login server/database error",
      status: false,
    });
  }
});

// ======================================================
// ADMIN PRODUCTS
// GET /admin/products
// ======================================================

router.get("/products", async (req, res) => {
  try {
    const [products] = await pool.query(
      "SELECT * FROM admin_products ORDER BY id DESC"
    );

    return res.status(200).json({
      success: true,
      count: products.length,
      products,
    });
  } catch (error) {
    console.error("ADMIN PRODUCTS API ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Products fetch nahi ho paaye.",
    });
  }
});

// ======================================================
// ADMIN: FETCH ALL ORDERS
// GET /admin/orders
// ======================================================

router.get("/orders", async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT *
      FROM orders
      ORDER BY id DESC
    `);

    return res.status(200).json({
      success: true,
      count: orders.length,
      orders,
    });
  } catch (error) {
    console.error("FETCH ALL ADMIN ORDERS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Orders fetch nahi ho paaye",
      error: error.message,
    });
  }
});

// ======================================================
// ADMIN: FETCH ALL SELLERS GST LEDGER
// GET /admin/gst-ledger
//
// Optional query parameters:
// seller_id, month, type, search
// ======================================================

router.get("/gst-ledger", verifyAdmin, async (req, res) => {
  try {
    const { seller_id, month, type, search } = req.query;

    let sql = `
      SELECT
        g.*,
        s.fullName AS seller_name,
        s.email AS seller_email,
        s.enrollmentNumber AS enrollment_number
      FROM gst_ledger g
      LEFT JOIN sellers s
        ON s.id = g.seller_id
      WHERE 1 = 1
    `;

    const params = [];

    // Filter by seller
    if (seller_id) {
      if (!/^\d+$/.test(String(seller_id))) {
        return res.status(400).json({
          success: false,
          message: "Invalid seller ID",
        });
      }

      sql += " AND g.seller_id = ?";
      params.push(Number(seller_id));
    }

    // Filter by month: YYYY-MM
    if (month) {
      if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(String(month))) {
        return res.status(400).json({
          success: false,
          message: "Month format must be YYYY-MM",
        });
      }

      sql += `
        AND DATE_FORMAT(g.transaction_date, '%Y-%m') = ?
      `;

      params.push(month);
    }

    // Filter by transaction type
    if (type) {
      if (!["Sales", "Purchase"].includes(String(type))) {
        return res.status(400).json({
          success: false,
          message: "Type must be Sales or Purchase",
        });
      }

      sql += " AND g.transaction_type = ?";
      params.push(type);
    }

    // Search invoice, party, GSTIN, notes and seller
    if (search && String(search).trim()) {
      const value = `%${String(search).trim()}%`;

      sql += `
        AND (
          g.invoice_number LIKE ?
          OR g.party_name LIKE ?
          OR g.gstin LIKE ?
          OR g.notes LIKE ?
          OR s.fullName LIKE ?
          OR s.email LIKE ?
          OR s.enrollmentNumber LIKE ?
        )
      `;

      params.push(
        value,
        value,
        value,
        value,
        value,
        value,
        value
      );
    }

    sql += `
      ORDER BY g.transaction_date DESC, g.id DESC
    `;

    const [rows] = await pool.query(sql, params);

    // Summary of fetched records
    const summary = rows.reduce(
      (acc, row) => {
        const amount = Number(row.total_amount || 0);
        const taxable = Number(row.taxable_amount || 0);
        const gst = Number(
          row.cgst || 0
        ) + Number(
          row.sgst || 0
        ) + Number(
          row.igst || 0
        );

        acc.total_transactions += 1;
        acc.total_taxable_amount += taxable;
        acc.total_gst += gst;
        acc.total_invoice_amount += amount;

        if (row.transaction_type === "Sales") {
          acc.total_sales += amount;
        }

        if (row.transaction_type === "Purchase") {
          acc.total_purchase += amount;
        }

        return acc;
      },
      {
        total_transactions: 0,
        total_taxable_amount: 0,
        total_gst: 0,
        total_invoice_amount: 0,
        total_sales: 0,
        total_purchase: 0,
      }
    );

    Object.keys(summary).forEach((key) => {
      if (key !== "total_transactions") {
        summary[key] = Number(summary[key].toFixed(2));
      }
    });

    return res.status(200).json({
      success: true,
      message: "GST Ledger fetched successfully",
      count: rows.length,
      summary,
      data: rows,
    });
  } catch (error) {
    console.error("ADMIN GST LEDGER FETCH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "GST Ledger fetch nahi ho saka.",
      error: error.message,
    });
  }
});

// ======================================================
// ADMIN: FETCH ALL SELLERS FOR GST DROPDOWN
// GET /admin/sellers
// ======================================================

router.get("/sellers", verifyAdmin, async (req, res) => {
  try {
    const [sellers] = await pool.query(`
      SELECT
        id,
        fullName,
        email,
        enrollmentNumber
      FROM sellers
      ORDER BY id DESC
    `);

    return res.status(200).json({
      success: true,
      message: "Sellers fetched successfully",
      count: sellers.length,
      sellers,
      data: sellers
    });

  } catch (error) {
    console.error("ADMIN GST SELLERS FETCH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Seller list fetch nahi ho saki.",
      error: error.message
    });
  }
});

// ======================================================
// ADMIN: SELLER PACKAGES
// GET /admin/seller-packages
//
// Shows which seller purchased which package, when it was
// purchased and when it expires.
//
// Optional query parameters:
//   status    = active | expiring | expired
//   seller_id = numeric seller ID
//   search    = seller name / email / mobile / enrollment / package
//
// ASSUMED TABLES (rename to match your database):
//   seller_packages (id, seller_id, package_id, amount_paid,
//                    purchase_date, expiry_date)
//   packages        (id, package_name, duration_days)
//
// If expiry_date is empty, it is calculated as
// purchase_date + duration_days.
// ======================================================

const PACKAGE_EXPIRING_SOON_DAYS = 7;

router.get("/seller-packages", verifyAdmin, async (req, res) => {
  try {
    const { status, seller_id, search } = req.query;

    let sql = `
      SELECT *
      FROM (
        SELECT
          sp.id,
          sp.seller_id,
          s.fullName AS seller_name,
          s.email AS seller_email,
          s.mobile AS seller_phone,
          s.enrollmentNumber AS enrollment_number,
          p.id AS package_id,
          p.package_name AS package_name,
          p.duration_days AS duration_days,
          sp.amount_paid AS amount_paid,
          sp.purchase_date AS purchase_date,
          COALESCE(
            sp.expiry_date,
            DATE_ADD(sp.purchase_date, INTERVAL p.duration_days DAY)
          ) AS expiry_date
        FROM seller_packages sp
        LEFT JOIN sellers s ON s.id = sp.seller_id
        LEFT JOIN packages p ON p.id = sp.package_id
      ) t
      WHERE 1 = 1
    `;

    const params = [];

    if (seller_id) {
      if (!/^\d+$/.test(String(seller_id))) {
        return res.status(400).json({
          success: false,
          message: "Invalid seller ID",
        });
      }

      sql += " AND t.seller_id = ?";
      params.push(Number(seller_id));
    }

    if (status) {
      if (!["active", "expiring", "expired"].includes(String(status))) {
        return res.status(400).json({
          success: false,
          message: "Status must be active, expiring or expired",
        });
      }

      if (status === "expired") {
        sql += " AND t.expiry_date < NOW()";
      } else if (status === "expiring") {
        sql += `
          AND t.expiry_date >= NOW()
          AND t.expiry_date <= DATE_ADD(NOW(), INTERVAL ? DAY)
        `;
        params.push(PACKAGE_EXPIRING_SOON_DAYS);
      } else {
        sql += `
          AND t.expiry_date > DATE_ADD(NOW(), INTERVAL ? DAY)
        `;
        params.push(PACKAGE_EXPIRING_SOON_DAYS);
      }
    }

    if (search && String(search).trim()) {
      const value = `%${String(search).trim()}%`;

      sql += `
        AND (
          t.seller_name LIKE ?
          OR t.seller_email LIKE ?
          OR t.seller_phone LIKE ?
          OR t.enrollment_number LIKE ?
          OR t.package_name LIKE ?
        )
      `;

      params.push(value, value, value, value, value);
    }

    sql += " ORDER BY t.purchase_date DESC, t.id DESC";

    const [rows] = await pool.query(sql, params);

    const now = Date.now();
    const soonLimit = now + PACKAGE_EXPIRING_SOON_DAYS * 86400000;

    const summary = rows.reduce(
      (acc, row) => {
        const expiry = row.expiry_date
          ? new Date(row.expiry_date).getTime()
          : null;

        acc.total += 1;

        if (expiry === null) return acc;

        if (expiry < now) acc.expired += 1;
        else if (expiry <= soonLimit) acc.expiring += 1;
        else acc.active += 1;

        return acc;
      },
      { total: 0, active: 0, expiring: 0, expired: 0 }
    );

    return res.status(200).json({
      success: true,
      message: "Seller packages fetched successfully",
      count: rows.length,
      summary,
      data: rows,
    });
  } catch (error) {
    console.error("ADMIN SELLER PACKAGES ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Could not fetch seller packages.",
      error: error.message,
    });
  }
});

// ======================================================
// SELLER PRODUCT APPROVAL SYSTEM
// ======================================================

// GET /admin/seller-products/pending
// Admin: Fetch pending seller products

router.get("/seller-products/pending", verifyAdmin, async (req, res) => {
  try {
    const [products] = await pool.query(`
      SELECT
        p.*,
        s.fullName AS seller_name,
        s.email AS seller_email,
        s.mobile AS seller_mobile,
        s.enrollmentNumber AS enrollment_number
      FROM dropshy_seller_products p
      LEFT JOIN sellers s ON s.id = p.seller_id
      WHERE p.status = 'pending'
      ORDER BY p.created_at DESC
    `);

    return res.json({
      success: true,
      message: "Pending products fetched successfully",
      count: products.length,
      products
    });

  } catch (error) {
    console.error("PENDING PRODUCTS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Could not fetch pending products"
    });
  }
});


// GET /admin/seller-products
// Admin: Fetch all seller products with filters

router.get("/seller-products", verifyAdmin, async (req, res) => {
  try {
    const { status, search } = req.query;

    let sql = `
      SELECT
        p.*,
        s.fullName AS seller_name,
        s.email AS seller_email,
        s.mobile AS seller_mobile,
        s.enrollmentNumber AS enrollment_number
      FROM dropshy_seller_products p
      LEFT JOIN sellers s ON s.id = p.seller_id
      WHERE 1 = 1
    `;

    const params = [];

    if (status) {
      const allowedStatuses = [
        "pending",
        "active",
        "inactive",
        "rejected",
        "out_of_stock"
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid product status"
        });
      }

      sql += " AND p.status = ?";
      params.push(status);
    }

    if (search && String(search).trim()) {
      const value = `%${String(search).trim()}%`;

      sql += `
        AND (
          p.product_name LIKE ?
          OR p.sku LIKE ?
          OR s.fullName LIKE ?
          OR s.email LIKE ?
        )
      `;

      params.push(value, value, value, value);
    }

    sql += " ORDER BY p.id DESC";

    const [products] = await pool.query(sql, params);

    return res.json({
      success: true,
      count: products.length,
      products
    });

  } catch (error) {
    console.error("ALL SELLER PRODUCTS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Could not fetch seller products"
    });
  }
});


// PATCH /admin/seller-products/:id/approve
// Admin: Approve seller product

router.patch(
  "/seller-products/:id/approve",
  verifyAdmin,
  async (req, res) => {
    try {
      const productId = req.params.id;
      const adminId = req.admin.id;

      if (!/^[1-9]\d*$/.test(productId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid product ID"
        });
      }

      const [products] = await pool.query(
        `SELECT id, status
         FROM dropshy_seller_products
         WHERE id = ?
         LIMIT 1`,
        [productId]
      );

      if (!products.length) {
        return res.status(404).json({
          success: false,
          message: "Product not found"
        });
      }

      if (products[0].status !== "pending") {
        return res.status(400).json({
          success: false,
          message: "Only pending products can be approved"
        });
      }

      await pool.query(
        `UPDATE dropshy_seller_products
         SET status = 'active',
             admin_remarks = NULL,
             approved_by = ?,
             approved_at = NOW(),
             updated_at = NOW()
         WHERE id = ?`,
        [adminId, productId]
      );

      return res.json({
        success: true,
        message: "Product approved successfully",
        product_id: Number(productId),
        status: "active"
      });

    } catch (error) {
      console.error("APPROVE PRODUCT ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Could not approve product"
      });
    }
  }
);


// PATCH /admin/seller-products/:id/reject
// Admin: Reject seller product

router.patch(
  "/seller-products/:id/reject",
  verifyAdmin,
  async (req, res) => {
    try {
      const productId = req.params.id;
      const adminId = req.admin.id;

      const reason = String(
        req.body?.reason || req.body?.admin_remarks || ""
      ).trim();

      if (!/^[1-9]\d*$/.test(productId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid product ID"
        });
      }

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Rejection reason is required"
        });
      }

      if (reason.length > 2000) {
        return res.status(400).json({
          success: false,
          message: "Rejection reason cannot exceed 2000 characters"
        });
      }

      const [products] = await pool.query(
        `SELECT id, status
         FROM dropshy_seller_products
         WHERE id = ?
         LIMIT 1`,
        [productId]
      );

      if (!products.length) {
        return res.status(404).json({
          success: false,
          message: "Product not found"
        });
      }

      if (products[0].status !== "pending") {
        return res.status(400).json({
          success: false,
          message: "Only pending products can be rejected"
        });
      }

      await pool.query(
        `UPDATE dropshy_seller_products
         SET status = 'rejected',
             admin_remarks = ?,
             approved_by = ?,
             approved_at = NULL,
             updated_at = NOW()
         WHERE id = ?`,
        [reason, adminId, productId]
      );

      return res.json({
        success: true,
        message: "Product rejected successfully",
        product_id: Number(productId),
        status: "rejected",
        admin_remarks: reason
      });

    } catch (error) {
      console.error("REJECT PRODUCT ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Could not reject product"
      });
    }
  }
);

// ======================================================
// SUPPORT TICKETS - ADMIN
// GET /admin/tickets
// PATCH /admin/tickets/:id/status
// ======================================================

// GET ALL SUPPORT TICKETS
router.get("/tickets", verifyAdmin, async (req, res) => {
  try {
    const { status, search } = req.query;

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(
      1000,
      Math.max(1, parseInt(req.query.limit) || 20)
    );

    const offset = (page - 1) * limit;

    const where = [];
    const params = [];

    if (status && status !== "all") {
      where.push("t.status = ?");
      params.push(status);
    }

    if (search && String(search).trim()) {
      const q = `%${String(search).trim()}%`;

      where.push(`(
        t.ticket_number LIKE ?
        OR t.order_awb LIKE ?
        OR t.category LIKE ?
        OR t.message LIKE ?
        OR s.fullName LIKE ?
        OR s.email LIKE ?
        OR s.enrollmentNumber LIKE ?
      )`);

      params.push(q, q, q, q, q, q, q);
    }

    const whereSql = where.length
      ? `WHERE ${where.join(" AND ")}`
      : "";

    const [tickets] = await pool.query(
      `SELECT
        t.id,
        t.ticket_number AS ticketNumber,
        t.seller_id AS sellerId,
        t.category,
        t.order_awb AS orderId,
        t.order_awb AS orderAwb,
        t.message,
        t.attachment,
        t.status,
        t.created_at AS createdAt,
        t.updated_at AS updatedAt,
        s.fullName AS sellerName,
        s.enrollmentNumber AS enrollmentNumber,
        s.mobile AS mobile,
        s.email AS email
      FROM support_tickets t
      LEFT JOIN sellers s ON s.id = t.seller_id
      ${whereSql}
      ORDER BY t.id DESC
      LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    const [[countResult]] = await pool.query(
      `SELECT COUNT(*) AS total
       FROM support_tickets t
       LEFT JOIN sellers s ON s.id = t.seller_id
       ${whereSql}`,
      params
    );

    return res.status(200).json({
      success: true,
      total: Number(countResult.total),
      page,
      limit,
      tickets,
    });

  } catch (error) {
    console.error("ADMIN FETCH TICKETS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch support tickets.",
      error: error.message,
    });
  }
});


// UPDATE TICKET STATUS
router.patch(
  "/tickets/:id/status",
  verifyAdmin,
  async (req, res) => {
    try {
      const ticketId = Number(req.params.id);

      const status = String(
        req.body.status || ""
      ).toLowerCase();

      if (!Number.isInteger(ticketId) || ticketId <= 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid ticket ID.",
        });
      }

      if (!["open", "in_progress", "waiting_for_seller", "resolved", "closed"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid ticket status.",
        });
      }

      const [[ticket]] = await pool.query(
        `SELECT id, seller_id, ticket_number
         FROM support_tickets
         WHERE id = ?
         LIMIT 1`,
        [ticketId]
      );

      if (!ticket) {
        return res.status(404).json({
          success: false,
          message: "Ticket not found.",
        });
      }

      await pool.query(
        `UPDATE support_tickets
         SET status = ?, updated_at = NOW()
         WHERE id = ?`,
        [status, ticketId]
      );

      try {
        await pool.query(
          `INSERT INTO notifications
          (
            seller_id,
            title,
            message,
            notification_type,
            reference_type,
            reference_id,
            is_read
          )
          VALUES (?, ?, ?, 'support_ticket', 'support_ticket', ?, 0)`,
          [
            ticket.seller_id,
            "Ticket Updated",
            `Your support ticket ${ticket.ticket_number} is now ${status}.`,
            ticketId,
          ]
        );
      } catch (notificationError) {
        console.error(
          "ADMIN TICKET NOTIFICATION ERROR:",
          notificationError
        );
      }

      return res.status(200).json({
        success: true,
        message: "Ticket status updated successfully.",
        ticketId,
        status,
      });

    } catch (error) {
      console.error("ADMIN UPDATE TICKET STATUS ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to update ticket status.",
        error: error.message,
      });
    }
  }
);


// ======================================================
// SUPPORT TICKETS - CONVERSATION AND REPLY
// GET  /admin/tickets/:id
// POST /admin/tickets/:id/replies
// ======================================================

const UPLOAD_DIR = path.resolve(__dirname, "../../uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const EXTENSIONS = {
  "image/jpeg": ".jpg",
  "image/png": ".png",
  "application/pdf": ".pdf",
};

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) =>
      cb(null, `${crypto.randomUUID()}${EXTENSIONS[file.mimetype]}`),
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) =>
    EXTENSIONS[file.mimetype]
      ? cb(null, true)
      : cb(new Error("Only JPG, PNG and PDF files are allowed.")),
});

const removeFile = (file) => file?.path && fs.unlink(file.path, () => {});

const fail = (res, status, message) =>
  res.status(status).json({ success: false, message });

async function findTicket(id) {
  const [rows] = await pool.query(
    `SELECT id, ticket_number AS ticketNumber, seller_id AS sellerId,
            category, category AS subject, order_awb AS orderId,
            order_awb AS orderAwb, message, attachment, status,
            created_at AS createdAt, updated_at AS updatedAt
     FROM support_tickets
     WHERE ticket_number = ? OR id = ?
     LIMIT 1`,
    [id, id]
  );
  return rows[0];
}

// GET /admin/tickets/:id
router.get("/tickets/:id", verifyAdmin, async (req, res) => {
  try {
    const ticket = await findTicket(req.params.id);
    if (!ticket) return fail(res, 404, "Ticket not found.");

    const [replies] = await pool.query(
      `SELECT id, ticket_id AS ticketId, sender_type AS senderType,
              sender_id AS senderId, message, attachment,
              created_at AS createdAt
       FROM support_ticket_replies
       WHERE ticket_id = ?
       ORDER BY id ASC`,
      [ticket.id]
    );

    return res.json({ success: true, ticket, replies });
  } catch (error) {
    console.error("ADMIN FETCH TICKET ERROR:", error);
    return fail(res, 500, "Unable to load ticket conversation.");
  }
});

// POST /admin/tickets/:id/replies
router.post(
  "/tickets/:id/replies",
  verifyAdmin,
  (req, res, next) => {
    upload.single("attachment")(req, res, (error) =>
      error ? fail(res, 400, error.message) : next()
    );
  },
  async (req, res) => {
    const reject = (status, message) => {
      removeFile(req.file);
      return fail(res, status, message);
    };

    try {
      const message = String(req.body?.message || "").trim();
      if (!message) return reject(400, "Reply message is required.");
      if (message.length > 500) {
        return reject(400, "Reply cannot exceed 500 characters.");
      }

      const ticket = await findTicket(req.params.id);
      if (!ticket) return reject(404, "Ticket not found.");

      if (["closed", "resolved"].includes(String(ticket.status).toLowerCase())) {
        return reject(400, "This ticket is closed.");
      }

      const adminId = req.admin.id;
      if (!adminId) return reject(401, "Admin ID not found.");

      const attachment = req.file ? `uploads/${req.file.filename}` : null;

      const [result] = await pool.query(
        `INSERT INTO support_ticket_replies
           (ticket_id, sender_type, sender_id, message, attachment)
         VALUES (?, 'admin', ?, ?, ?)`,
        [ticket.id, adminId, message, attachment]
      );

      // Reply save ho chuki hai; neeche ki error se request fail nahi honi chahiye
      try {
        await pool.query(
          "UPDATE support_tickets SET updated_at = NOW() WHERE id = ?",
          [ticket.id]
        );
        await pool.query(
          `INSERT INTO notifications
             (seller_id, title, message, notification_type,
              reference_type, reference_id, is_read)
           VALUES (?, ?, ?, 'support_ticket', 'support_ticket', ?, 0)`,
          [
            ticket.sellerId,
            "Support Ticket Reply",
            `Support replied to your ticket ${ticket.ticketNumber}.`,
            ticket.id,
          ]
        );
      } catch (sideError) {
        console.error("ADMIN REPLY FOLLOW-UP ERROR:", sideError);
      }

      return res.status(201).json({
        success: true,
        message: "Reply sent successfully.",
        reply: {
          id: result.insertId,
          ticketId: ticket.id,
          senderType: "admin",
          senderId: adminId,
          message,
          attachment,
          createdAt: new Date(),
        },
      });
    } catch (error) {
      console.error("ADMIN TICKET REPLY ERROR:", error);
      return reject(500, "Unable to send ticket reply.");
    }
  }
);
// ======================================================
// CALL SUPPORT - ADMIN
// GET   /admin/call-support/managers
// GET   /admin/call-support/stats
// GET   /admin/call-support/calendar?month=YYYY-MM
// GET   /admin/call-support/slots-summary?date=YYYY-MM-DD
// GET   /admin/call-support/slots?date=YYYY-MM-DD&manager=ID
// GET   /admin/call-support/bookings
// POST  /admin/call-support/bookings
// PATCH /admin/call-support/bookings/:id/status
//
// Tables: support_bookings, support_slots, support_managers, sellers
// (PASTE THIS BLOCK just above `module.exports = router;`)
// ======================================================

const CS_ISO = /^\d{4}-\d{2}-\d{2}$/;
const CS_STATUSES = ["Confirmed", "Completed", "Cancelled"];

// sellers table columns
const CS_S_NAME = "s.fullName";
const CS_S_PHONE = "s.mobile";
const CS_S_PHOTO = "NULL"; // photo URL column ho to e.g. s.profilePhoto
const CS_S_CODE = "COALESCE(NULLIF(s.enrollmentNumber, ''), CONCAT('SLR-', s.id))";

const csOk = (res, data = {}) => res.json({ success: true, ...data });
const csFail = (res, code, message) =>
  res.status(code).json({ success: false, message });
const csWrap = (fn) => (req, res) =>
  fn(req, res).catch((error) => {
    console.error("ADMIN CALL SUPPORT ERROR:", error);
    csFail(res, 500, "Server error");
  });

function csToday() {
  const n = new Date();
  return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, "0")}-${String(n.getDate()).padStart(2, "0")}`;
}

function csWorkingDay(dateString, workingDays) {
  const day = new Date(`${dateString}T12:00:00`).getDay();
  const days = String(workingDays || "Monday-Saturday").toLowerCase();
  if (days.includes("monday-friday")) return day >= 1 && day <= 5;
  return day >= 1 && day <= 6;
}

const csToMin = (t) => {
  const p = String(t).slice(0, 8).split(":");
  return Number(p[0]) * 60 + Number(p[1]);
};
const csToTime = (m) =>
  `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}:00`;

// seller wale router jaisa slot generation (30 min)
async function csGenerateSlots(date, manager) {
  const [existing] = await pool.query(
    "SELECT id FROM support_slots WHERE manager_id = ? AND slot_date = ? LIMIT 1",
    [manager.id, date]
  );
  if (existing.length || !csWorkingDay(date, manager.working_days)) return;

  const start = csToMin(manager.start_time);
  const end = csToMin(manager.end_time);
  const values = [];

  for (let m = start; m + 30 <= end; m += 30) {
    values.push([manager.id, date, csToTime(m), csToTime(m + 30)]);
  }

  if (values.length) {
    await pool.query(
      "INSERT IGNORE INTO support_slots (manager_id, slot_date, start_time, end_time) VALUES ?",
      [values]
    );
  }
}

// GET managers
router.get(
  "/call-support/managers",
  verifyAdmin,
  csWrap(async (req, res) => {
    const [managers] = await pool.query(
      "SELECT id, name, phone FROM support_managers WHERE is_active = 1 ORDER BY name"
    );
    csOk(res, { managers });
  })
);

// GET stats (last 30 days vs previous 30)
router.get(
  "/call-support/stats",
  verifyAdmin,
  csWrap(async (req, res) => {
    const cur = "created_at >= NOW() - INTERVAL 30 DAY";
    const prev =
      "created_at < NOW() - INTERVAL 30 DAY AND created_at >= NOW() - INTERVAL 60 DAY";
    const UP = "(status = 'Confirmed' AND booking_date >= CURDATE())";

    const [[r]] = await pool.query(`
      SELECT
        COUNT(*) total,
        COALESCE(SUM(status = 'Completed'), 0) completed,
        COALESCE(SUM(${UP}), 0) upcoming,
        COALESCE(SUM(status = 'Cancelled'), 0) cancelled,
        COALESCE(SUM(${cur}), 0) c_total,
        COALESCE(SUM(${prev}), 0) p_total,
        COALESCE(SUM(status = 'Completed' AND ${cur}), 0) c_completed,
        COALESCE(SUM(status = 'Completed' AND ${prev}), 0) p_completed,
        COALESCE(SUM(${UP} AND ${cur}), 0) c_upcoming,
        COALESCE(SUM(${UP} AND ${prev}), 0) p_upcoming,
        COALESCE(SUM(status = 'Cancelled' AND ${cur}), 0) c_cancelled,
        COALESCE(SUM(status = 'Cancelled' AND ${prev}), 0) p_cancelled
      FROM support_bookings`);

    const pct = (c, p) => {
      c = Number(c);
      p = Number(p);
      return !p ? (c ? null : 0) : Math.round(((c - p) / p) * 100);
    };

    csOk(res, {
      stats: {
        total: { value: Number(r.total), delta: pct(r.c_total, r.p_total) },
        completed: { value: Number(r.completed), delta: pct(r.c_completed, r.p_completed) },
        upcoming: { value: Number(r.upcoming), delta: pct(r.c_upcoming, r.p_upcoming) },
        cancelled: { value: Number(r.cancelled), delta: pct(r.c_cancelled, r.p_cancelled) },
      },
    });
  })
);

// GET calendar: booked dates of a month
router.get(
  "/call-support/calendar",
  verifyAdmin,
  csWrap(async (req, res) => {
    const month = String(req.query.month || "");
    if (!/^\d{4}-\d{2}$/.test(month)) return csFail(res, 400, "Invalid month");

    const [rows] = await pool.query(
      `SELECT DISTINCT DATE_FORMAT(booking_date, '%Y-%m-%d') d
       FROM support_bookings
       WHERE DATE_FORMAT(booking_date, '%Y-%m') = ?
         AND status <> 'Cancelled'`,
      [month]
    );
    csOk(res, { dates: rows.map((x) => x.d) });
  })
);

// GET slot summary of a date
router.get(
  "/call-support/slots-summary",
  verifyAdmin,
  csWrap(async (req, res) => {
    const date = CS_ISO.test(req.query.date || "") ? req.query.date : csToday();

    if (date >= csToday()) {
      const [managers] = await pool.query(
        `SELECT id, working_days, start_time, end_time
         FROM support_managers WHERE is_active = 1`
      );
      for (const m of managers) await csGenerateSlots(date, m);
    }

    const [[r]] = await pool.query(
      `SELECT COUNT(*) total,
              COALESCE(SUM(sl.is_available = 0), 0) booked,
              COALESCE(SUM(sl.is_available = 1
                AND (sl.slot_date > CURDATE() OR sl.start_time > CURTIME())), 0) available
       FROM support_slots sl
       JOIN support_managers m ON m.id = sl.manager_id AND m.is_active = 1
       WHERE sl.slot_date = ?`,
      [date]
    );

    csOk(res, {
      total: Number(r.total),
      booked: Number(r.booked),
      available: Number(r.available),
    });
  })
);

// GET slots of a manager on a date (manual booking)
router.get(
  "/call-support/slots",
  verifyAdmin,
  csWrap(async (req, res) => {
    const date = req.query.date;
    if (!CS_ISO.test(date || "") || date < csToday()) {
      return csFail(res, 400, "Please select a valid current or future date.");
    }

    const [[manager]] = await pool.query(
      `SELECT id, working_days, start_time, end_time
       FROM support_managers WHERE id = ? AND is_active = 1`,
      [Number(req.query.manager)]
    );
    if (!manager) return csFail(res, 404, "Manager not found.");

    if (!csWorkingDay(date, manager.working_days)) {
      return csOk(res, { slots: [], message: "Support is not available on this day." });
    }

    await csGenerateSlots(date, manager);

    const [slots] = await pool.query(
      `SELECT id,
              TIME_FORMAT(start_time, '%H:%i:%s') AS start_time,
              TIME_FORMAT(end_time, '%H:%i:%s') AS end_time,
              is_available
       FROM support_slots
       WHERE manager_id = ? AND slot_date = ?
       ORDER BY start_time ASC`,
      [manager.id, date]
    );

    const now = new Date();
    const nowMin = now.getHours() * 60 + now.getMinutes();

    csOk(res, {
      slots: slots.map((s) => ({
        ...s,
        is_available:
          Boolean(s.is_available) &&
          !(date === csToday() && csToMin(s.start_time) <= nowMin),
      })),
    });
  })
);

// GET bookings (filters + pagination)
router.get(
  "/call-support/bookings",
  verifyAdmin,
  csWrap(async (req, res) => {
    const q = req.query;
    const where = ["1 = 1"];
    const params = [];

    if (q.tab === "upcoming") where.push("(b.status = 'Confirmed' AND b.booking_date >= CURDATE())");
    else if (q.tab === "completed") where.push("b.status = 'Completed'");
    else if (q.tab === "cancelled") where.push("b.status = 'Cancelled'");

    if (CS_STATUSES.includes(q.status)) {
      where.push("b.status = ?");
      params.push(q.status);
    }
    if (q.manager) {
      where.push("b.manager_id = ?");
      params.push(Number(q.manager));
    }
    if (CS_ISO.test(q.date || "")) {
      where.push("b.booking_date = ?");
      params.push(q.date);
    } else {
      if (CS_ISO.test(q.from || "")) { where.push("b.booking_date >= ?"); params.push(q.from); }
      if (CS_ISO.test(q.to || "")) { where.push("b.booking_date <= ?"); params.push(q.to); }
    }
    if (q.q && String(q.q).trim()) {
      const like = `%${String(q.q).trim()}%`;
      where.push(`(${CS_S_NAME} LIKE ? OR ${CS_S_PHONE} LIKE ? OR s.email LIKE ?
                   OR s.enrollmentNumber LIKE ? OR b.booking_reference LIKE ?)`);
      params.push(like, like, like, like, like);
    }

    const limit = Math.min(Math.max(parseInt(q.limit, 10) || 10, 1), 100);
    const page = Math.max(parseInt(q.page, 10) || 1, 1);
    const W = where.join(" AND ");
    const FROM = `FROM support_bookings b
                  JOIN sellers s ON s.id = b.seller_id
                  LEFT JOIN support_managers m ON m.id = b.manager_id`;

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) total ${FROM} WHERE ${W}`, params
    );

    const [rows] = await pool.query(
      `SELECT b.id, b.booking_reference, b.seller_id,
              ${CS_S_CODE} AS seller_code,
              ${CS_S_NAME} AS seller_name,
              ${CS_S_PHONE} AS seller_phone,
              ${CS_S_PHOTO} AS seller_photo,
              b.manager_id, m.name AS manager_name, m.phone AS manager_phone,
              DATE_FORMAT(b.booking_date, '%Y-%m-%d') AS booking_date,
              TIME_FORMAT(b.start_time, '%H:%i:%s') AS start_time,
              TIME_FORMAT(b.end_time, '%H:%i:%s') AS end_time,
              b.support_type, b.status
       ${FROM}
       WHERE ${W}
       ORDER BY b.booking_date DESC, b.start_time DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, (page - 1) * limit]
    );

    csOk(res, { rows, total: Number(total) });
  })
);

// POST manual booking (admin books a slot for a seller)
router.post(
  "/call-support/bookings",
  verifyAdmin,
  csWrap(async (req, res) => {
    const { seller, slot_id, support_type } = req.body || {};
    const slotId = Number(slot_id);
    const type = String(support_type || "").trim();
    const sellerText = String(seller || "").trim();

    if (!sellerText) return csFail(res, 400, "Seller ID / enrollment number required.");
    if (!slotId || !type) return csFail(res, 400, "Slot and support type are required.");

    // "SLR-12" / "12" => seller id, ya enrollment number
    const idMatch = sellerText.match(/^(?:SLR-)?(\d+)$/i);
    const [[s]] = await pool.query(
      "SELECT id FROM sellers WHERE enrollmentNumber = ? OR id = ? LIMIT 1",
      [sellerText, idMatch ? Number(idMatch[1]) : 0]
    );
    if (!s) return csFail(res, 404, "Seller not found.");

    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const [slotRows] = await connection.query(
        "SELECT * FROM support_slots WHERE id = ? FOR UPDATE", [slotId]
      );
      const slot = slotRows[0];

      if (!slot || !slot.is_available) {
        await connection.rollback();
        return csFail(res, 409, "This slot is no longer available.");
      }

      const [upd] = await connection.query(
        "UPDATE support_slots SET is_available = 0 WHERE id = ? AND is_available = 1",
        [slot.id]
      );
      if (upd.affectedRows !== 1) {
        await connection.rollback();
        return csFail(res, 409, "This slot has just been booked.");
      }

      const reference = "CS" + Date.now() + Math.floor(1000 + Math.random() * 9000);

      const [r] = await connection.query(
        `INSERT INTO support_bookings
           (booking_reference, seller_id, manager_id, slot_id,
            booking_date, start_time, end_time, support_type, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Confirmed')`,
        [reference, s.id, slot.manager_id, slot.id,
         slot.slot_date, slot.start_time, slot.end_time, type]
      );

      await connection.commit();
      csOk(res, { id: r.insertId, booking_reference: reference });
    } catch (error) {
      await connection.rollback();
      if (error.code === "ER_DUP_ENTRY") {
        return csFail(res, 409, "This slot is already booked.");
      }
      throw error;
    } finally {
      connection.release();
    }
  })
);

// ======================================================
// CALL SUPPORT - BOOKING DETAILS
// GET /admin/call-support/bookings/:id
// PATCH /admin/call-support/bookings/:id/note
// ======================================================

// GET COMPLETE BOOKING DETAILS
router.get(
  "/call-support/bookings/:id",
  verifyAdmin,
  csWrap(async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return csFail(res, 400, "Invalid booking ID.");
    }

    const [rows] = await pool.query(
      `SELECT
          b.*,
          ${CS_S_CODE} AS seller_code,
          ${CS_S_NAME} AS seller_name,
          ${CS_S_PHONE} AS seller_phone,
          s.email AS seller_email,
          ${CS_S_PHOTO} AS seller_photo,
          m.name AS manager_name,
          m.phone AS manager_phone
       FROM support_bookings b
       LEFT JOIN sellers s ON s.id = b.seller_id
       LEFT JOIN support_managers m ON m.id = b.manager_id
       WHERE b.id = ?
       LIMIT 1`,
      [id]
    );

    if (!rows.length) {
      return csFail(res, 404, "Booking not found.");
    }

    const booking = rows[0];

    csOk(res, { booking });
  })
);


// SAVE ADMIN NOTE
router.patch(
  "/call-support/bookings/:id/note",
  verifyAdmin,
  csWrap(async (req, res) => {
    const id = Number(req.params.id);
    const note = String(req.body?.admin_note || "").trim();

    if (!Number.isInteger(id) || id <= 0) {
      return csFail(res, 400, "Invalid booking ID.");
    }

    if (note.length > 500) {
      return csFail(res, 400, "Note cannot exceed 500 characters.");
    }

    const [result] = await pool.query(
      `UPDATE support_bookings
       SET admin_note = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [note || null, id]
    );

    if (!result.affectedRows) {
      return csFail(res, 404, "Booking not found.");
    }

    csOk(res, {
      message: "Admin note saved successfully.",
      admin_note: note,
    });
  })
);

// GET CALL SUPPORT BOOKING DETAILS
router.get(
  "/call-support/bookings/:id",
  verifyAdmin,
  csWrap(async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return csFail(res, 400, "Invalid booking ID.");
    }

    const [rows] = await pool.query(
      `SELECT
        b.*,
        ${CS_S_CODE} AS seller_code,
        ${CS_S_NAME} AS seller_name,
        ${CS_S_PHONE} AS seller_phone,
        s.email AS seller_email,
        m.name AS manager_name,
        m.phone AS manager_phone
       FROM support_bookings b
       LEFT JOIN sellers s ON s.id = b.seller_id
       LEFT JOIN support_managers m ON m.id = b.manager_id
       WHERE b.id = ?
       LIMIT 1`,
      [id]
    );

    if (!rows.length) {
      return csFail(res, 404, "Booking not found.");
    }

    csOk(res, { booking: rows[0] });
  })
);
// PATCH booking status: Confirmed -> Completed / Cancelled
router.patch(
  "/call-support/bookings/:id/status",
  verifyAdmin,
  csWrap(async (req, res) => {
    const id = Number(req.params.id);
    const status = req.body && req.body.status;

    if (!Number.isInteger(id) || id <= 0) return csFail(res, 400, "Invalid booking ID.");
    if (!["Completed", "Cancelled"].includes(status)) {
      return csFail(res, 400, "Status must be Completed or Cancelled.");
    }

    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const [rows] = await connection.query(
        "SELECT * FROM support_bookings WHERE id = ? FOR UPDATE", [id]
      );
      const booking = rows[0];

      if (!booking) {
        await connection.rollback();
        return csFail(res, 404, "Booking not found.");
      }
      if (booking.status !== "Confirmed") {
        await connection.rollback();
        return csFail(res, 400, "Only confirmed bookings can be updated.");
      }

      await connection.query(
        "UPDATE support_bookings SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [status, id]
      );

      if (status === "Cancelled") {
        await connection.query(
          "UPDATE support_slots SET is_available = 1 WHERE id = ?",
          [booking.slot_id]
        );
      }

      await connection.commit();
      csOk(res, { message: `Booking ${status.toLowerCase()}.` });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  })
);
module.exports = router;