
const express = require("express");
const router = express.Router();

const jwt = require("jsonwebtoken");
const pool = require("./pool");

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


module.exports = router;
