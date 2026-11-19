
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./pool");

const router = express.Router();

const JWT_SECRET =
  process.env.JWT_SECRET || "DROPSHY_ADMIN_SECRET_2026";

const ROLES = ["Customer", "Staff", "Sub Admin", "Admin"];

const MODULES = [
  "Dashboard",
  "User Management",
  "Seller Management",
  "Product Management",
  "Order Management",
  "Payment Management",
  "GST Management",
  "Support Tickets",
  "Reports",
  "Settings",
];

const normalizeRole = (role) => {
  const found = ROLES.find(
    (item) => item.toLowerCase() === String(role || "").trim().toLowerCase()
  );
  return found || null;
};

// =====================================================
// ADMIN AUTHENTICATION
// =====================================================

const adminAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        status: false,
        message: "Admin authentication required.",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const role = String(
      decoded.role || decoded.userRole || decoded.accountType || ""
    ).toLowerCase();

    if (role !== "admin") {
      return res.status(403).json({
        status: false,
        message: "Only Admin can manage user accounts.",
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
  console.error("CREATE USER ERROR:", error);

  return res.status(500).json({
    status: false,
    message: "Unable to create account.",
    error: error.message,
    code: error.code || null,
    sqlMessage: error.sqlMessage || null,
  });
}
};

// =====================================================
// REGISTER CUSTOMER - PUBLIC
// =====================================================

router.post("/users/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        status: false,
        message: "Name, email and password are required.",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [cleanEmail]
    );

    if (existing.length) {
      return res.status(409).json({
        status: false,
        message: "Email already registered.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users
       (name, email, phone, password, role, status)
       VALUES (?, ?, ?, ?, 'Customer', 'active')`,
      [
        name.trim(),
        cleanEmail,
        phone || null,
        hashedPassword,
      ]
    );

    return res.status(201).json({
      status: true,
      message: "Customer account created successfully.",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Registration failed.",
    });
  }
});

// =====================================================
// LOGIN USER
// =====================================================

router.post("/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: false,
        message: "Email and password are required.",
      });
    }

    const [users] = await pool.query(
      `SELECT id, name, email, phone, password, role, status
       FROM users
       WHERE email = ?`,
      [email.trim().toLowerCase()]
    );

    if (!users.length) {
      return res.status(401).json({
        status: false,
        message: "Invalid email or password.",
      });
    }

    const user = users[0];

    if (user.status === "inactive") {
      return res.status(403).json({
        status: false,
        message: "Your account has been deactivated.",
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        status: false,
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role || "Customer",
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      status: true,
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role || "Customer",
      },
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Login failed.",
    });
  }
});

// =====================================================
// GET ALL USERS - ADMIN ONLY
// =====================================================

router.get("/users/all", adminAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        id, name, email, phone, role, status,
        department, designation, reporting_manager,
        branch, employment_type, joining_date,
        permissions, created_at, updated_at
      FROM users
      ORDER BY id DESC
    `);

    return res.json({
      status: true,
      count: rows.length,
      users: rows.map((user) => ({
        ...user,
        permissions:
          typeof user.permissions === "string"
            ? JSON.parse(user.permissions || "[]")
            : user.permissions || [],
      })),
    });
  } catch (error) {
    console.error("FETCH USERS ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to fetch users.",
    });
  }
});

// =====================================================
// CREATE USER - ADMIN ONLY
// =====================================================

router.post("/users/create", adminAuth, async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      password,
      role,
      department,
      designation,
      reporting_manager,
      branch,
      employment_type,
      joining_date,
      permissions,
    } = req.body;

    const cleanRole = normalizeRole(role);
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!name || !cleanEmail || !phone || !password || !cleanRole) {
      return res.status(400).json({
        status: false,
        message: "Please provide all required details.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        status: false,
        message: "Password must contain at least 6 characters.",
      });
    }

    if (cleanRole === "Customer" && permissions?.length) {
      return res.status(400).json({
        status: false,
        message: "Customers cannot receive admin permissions.",
      });
    }

    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [cleanEmail]
    );

    if (existing.length) {
      return res.status(409).json({
        status: false,
        message: "Email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const safePermissions =
      ["Admin", "Sub Admin"].includes(cleanRole)
        ? (Array.isArray(permissions)
            ? permissions.filter((p) => MODULES.includes(p))
            : [])
        : [];

    const [result] = await pool.query(
      `INSERT INTO users (
        name, email, phone, password, role, status,
        department, designation, reporting_manager,
        branch, employment_type, joining_date, permissions
      ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
      [
        name.trim(),
        cleanEmail,
        phone,
        hashedPassword,
        cleanRole,
        department || null,
        designation || null,
        reporting_manager || null,
        branch || null,
        employment_type || null,
        joining_date || null,
        JSON.stringify(safePermissions),
      ]
    );

    return res.status(201).json({
      status: true,
      message: `${cleanRole} created successfully.`,
      userId: result.insertId,
    });
  } catch (error) {
    console.error("CREATE USER ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to create account.",
    });
  }
});

// =====================================================
// UPDATE USER - ADMIN ONLY
// =====================================================

router.put("/users/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const {
      name,
      email,
      phone,
      password,
      role,
      department,
      designation,
      reporting_manager,
      branch,
      employment_type,
      joining_date,
      permissions,
    } = req.body;

    const cleanRole = normalizeRole(role);
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!name || !cleanEmail || !phone || !cleanRole) {
      return res.status(400).json({
        status: false,
        message: "Name, email, phone and valid role are required.",
      });
    }

    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ? AND id != ?",
      [cleanEmail, id]
    );

    if (existing.length) {
      return res.status(409).json({
        status: false,
        message: "Email already exists.",
      });
    }

    const safePermissions =
      ["Admin", "Sub Admin"].includes(cleanRole)
        ? (Array.isArray(permissions)
            ? permissions.filter((p) => MODULES.includes(p))
            : [])
        : [];

    const values = [
      name.trim(),
      cleanEmail,
      phone,
      cleanRole,
      department || null,
      designation || null,
      reporting_manager || null,
      branch || null,
      employment_type || null,
      joining_date || null,
      JSON.stringify(safePermissions),
    ];

    let sql = `
      UPDATE users SET
        name = ?, email = ?, phone = ?, role = ?,
        department = ?, designation = ?,
        reporting_manager = ?, branch = ?,
        employment_type = ?, joining_date = ?,
        permissions = ?
    `;

    if (password) {
      if (password.length < 6) {
        return res.status(400).json({
          status: false,
          message: "Password must contain at least 6 characters.",
        });
      }

      values.push(await bcrypt.hash(password, 10));
      sql += ", password = ?";
    }

    sql += " WHERE id = ?";
    values.push(id);

    const [result] = await pool.query(sql, values);

    if (!result.affectedRows) {
      return res.status(404).json({
        status: false,
        message: "User not found.",
      });
    }

    return res.json({
      status: true,
      message: "User updated successfully.",
    });
  } catch (error) {
    console.error("UPDATE USER ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to update user.",
    });
  }
});

// =====================================================
// ACTIVATE / DEACTIVATE USER
// =====================================================

router.patch("/users/:id/status", adminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    if (!["active", "inactive"].includes(status)) {
      return res.status(400).json({
        status: false,
        message: "Invalid account status.",
      });
    }

    const [result] = await pool.query(
      "UPDATE users SET status = ? WHERE id = ?",
      [status, req.params.id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        status: false,
        message: "User not found.",
      });
    }

    return res.json({
      status: true,
      message: `Account ${status} successfully.`,
    });
  } catch (error) {
    console.error("STATUS UPDATE ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to update account status.",
    });
  }
});

module.exports = router;
