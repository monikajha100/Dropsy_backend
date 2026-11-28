
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./pool");

const router = express.Router();
const teamRouter = express.Router();

const JWT_SECRET =
  process.env.JWT_SECRET || "DROPSHY_ADMIN_SECRET_2026";

const ROLES = ["Customer", "Staff", "Sub Admin", "Admin"];

const TEAM_ROLES = ["admin", "manager", "staff"];

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

const normalizeRole = (role) =>
  ROLES.find(
    (item) =>
      item.toLowerCase() ===
      String(role || "").trim().toLowerCase()
  ) || null;

const normalizeTeamRole = (role) => {
  const value = String(role || "").trim().toLowerCase();

  if (value === "admin") return "Admin";
  if (value === "manager") return "Sub Admin";
  if (value === "staff") return "Staff";

  return null;
};

const toTeamRole = (role) => {
  const value = String(role || "").trim().toLowerCase();

  if (value === "admin") return "admin";
  if (value === "sub admin" || value === "manager") return "manager";
  if (value === "staff") return "staff";

  return value;
};

const parsePermissions = (permissions) => {
  if (Array.isArray(permissions)) return permissions;

  try {
    const parsed = JSON.parse(permissions || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const normalizePermissions = (role, permissions) => {
  if (!["Admin", "Sub Admin"].includes(role)) return [];

  if (!Array.isArray(permissions)) return [];

  return [...new Set(
    permissions.filter((permission) =>
      MODULES.includes(permission)
    )
  )];
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
      decoded.role ||
      decoded.userRole ||
      decoded.accountType ||
      ""
    ).toLowerCase();

    if (role !== "admin") {
      return res.status(403).json({
        status: false,
        message: "Only Admin can manage users.",
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    console.error("ADMIN AUTH ERROR:", error.message);

    return res.status(401).json({
      status: false,
      message: "Invalid or expired admin token.",
    });
  }
};

// =====================================================
// TEAM AUTHORIZATION
// =====================================================

const teamAuth = (req, res, next) => {
  return adminAuth(req, res, next);
};

// =====================================================
// REGISTER CUSTOMER
// =====================================================

router.post("/users/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (
      !String(name || "").trim() ||
      !String(email || "").trim() ||
      !password
    ) {
      return res.status(400).json({
        status: false,
        message: "Name, email and password are required.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        status: false,
        message: "Password must contain at least 6 characters.",
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
      `SELECT id, name, email, phone, password,
              role, status, department, designation,
              reporting_manager, branch, employment_type,
              joining_date, permissions
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

    if (user.status !== "active") {
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

    const safeUser = { ...user };
    delete safeUser.password;

    return res.json({
      status: true,
      message: "Login successful.",
      token,
      user: {
        ...safeUser,
        permissions: parsePermissions(user.permissions),
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
// GET ALL USERS
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
        permissions: parsePermissions(user.permissions),
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
// CREATE USER
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

    if (
      !String(name || "").trim() ||
      !cleanEmail ||
      !phone ||
      !password ||
      !cleanRole
    ) {
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

    const safePermissions = normalizePermissions(
      cleanRole,
      permissions
    );

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
// UPDATE USER
// =====================================================

router.put("/users/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        status: false,
        message: "Invalid user ID.",
      });
    }

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

    if (
      !String(name || "").trim() ||
      !cleanEmail ||
      !phone ||
      !cleanRole
    ) {
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
      JSON.stringify(
        normalizePermissions(cleanRole, permissions)
      ),
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

// =====================================================
// DELETE USER
// =====================================================

router.delete("/users/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        status: false,
        message: "Invalid user ID.",
      });
    }

    if (Number(id) === Number(req.admin.id)) {
      return res.status(400).json({
        status: false,
        message: "You cannot delete your own account.",
      });
    }

    const [result] = await pool.query(
      "DELETE FROM users WHERE id = ?",
      [id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        status: false,
        message: "User not found.",
      });
    }

    return res.json({
      status: true,
      message: "User deleted successfully.",
    });
  } catch (error) {
    console.error("DELETE USER ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to delete user.",
    });
  }
});

// =====================================================
// TEAM MANAGEMENT - GET PERMISSIONS
// GET /admin/team/permissions
// =====================================================

router.get("/team/permissions", teamAuth, async (req, res) => {
  try {
    return res.json({
      status: true,
      modules: MODULES,
      roles: TEAM_ROLES,
    });
  } catch (error) {
    console.error("TEAM PERMISSIONS ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to fetch team permissions.",
    });
  }
});

// =====================================================
// TEAM MANAGEMENT - GET MEMBERS
// GET /admin/team/members
// =====================================================

router.get("/team/members", teamAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
        id, name, email, phone, role, status,
        department, designation, reporting_manager,
        branch, employment_type, joining_date,
        permissions, created_at, updated_at
       FROM users
       WHERE role IN ('Admin', 'Sub Admin', 'Staff')
       ORDER BY id DESC`
    );

    const members = rows.map((user) => ({
      ...user,
      role: toTeamRole(user.role),
      permissions: parsePermissions(user.permissions),
    }));

    return res.json({
      status: true,
      count: members.length,
      members,
      users: members,
      data: members,
    });
  } catch (error) {
    console.error("FETCH TEAM MEMBERS ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to fetch team members.",
    });
  }
});

// =====================================================
// TEAM MANAGEMENT - ADD MEMBER
// POST /admin/team/members
// =====================================================

router.post("/team/members", teamAuth, async (req, res) => {
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

    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanRole = normalizeTeamRole(role);

    if (
      !String(name || "").trim() ||
      !cleanEmail ||
      !phone ||
      !password ||
      !cleanRole
    ) {
      return res.status(400).json({
        status: false,
        message: "Name, email, phone, password and valid role are required.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        status: false,
        message: "Password must contain at least 6 characters.",
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

    const safePermissions = normalizePermissions(
      cleanRole,
      permissions
    );

    const hashedPassword = await bcrypt.hash(password, 10);

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
      message: "Team member added successfully.",
      memberId: result.insertId,
      userId: result.insertId,
    });
  } catch (error) {
    console.error("ADD TEAM MEMBER ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to add team member.",
    });
  }
});

// =====================================================
// TEAM MANAGEMENT - UPDATE MEMBER
// PUT /admin/team/members/:id
// =====================================================

router.put("/team/members/:id", teamAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        status: false,
        message: "Invalid member ID.",
      });
    }

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

    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanRole = normalizeTeamRole(role);

    if (
      !String(name || "").trim() ||
      !cleanEmail ||
      !phone ||
      !cleanRole
    ) {
      return res.status(400).json({
        status: false,
        message: "Name, email, phone and valid role are required.",
      });
    }

    const [existing] = await pool.query(
      "SELECT id FROM users WHERE id = ? AND role IN ('Admin', 'Sub Admin', 'Staff')",
      [id]
    );

    if (!existing.length) {
      return res.status(404).json({
        status: false,
        message: "Team member not found.",
      });
    }

    const [duplicate] = await pool.query(
      "SELECT id FROM users WHERE email = ? AND id != ?",
      [cleanEmail, id]
    );

    if (duplicate.length) {
      return res.status(409).json({
        status: false,
        message: "Email already exists.",
      });
    }

    const safePermissions = normalizePermissions(
      cleanRole,
      permissions
    );

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

    await pool.query(sql, values);

    return res.json({
      status: true,
      message: "Team member updated successfully.",
    });
  } catch (error) {
    console.error("UPDATE TEAM MEMBER ERROR:", error);

    return res.status(500).json({
      status: false,
      message: "Unable to update team member.",
    });
  }
});

// =====================================================
// TEAM MANAGEMENT - STATUS
// PATCH /admin/team/members/:id/status
// =====================================================

router.patch(
  "/team/members/:id/status",
  teamAuth,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!/^\d+$/.test(id)) {
        return res.status(400).json({
          status: false,
          message: "Invalid member ID.",
        });
      }

      if (!["active", "inactive"].includes(status)) {
        return res.status(400).json({
          status: false,
          message: "Status must be active or inactive.",
        });
      }

      if (Number(id) === Number(req.admin.id)) {
        return res.status(400).json({
          status: false,
          message: "You cannot deactivate your own account.",
        });
      }

      const [result] = await pool.query(
        `UPDATE users
         SET status = ?
         WHERE id = ?
         AND role IN ('Admin', 'Sub Admin', 'Staff')`,
        [status, id]
      );

      if (!result.affectedRows) {
        return res.status(404).json({
          status: false,
          message: "Team member not found.",
        });
      }

      return res.json({
        status: true,
        message: `Team member ${status} successfully.`,
      });
    } catch (error) {
      console.error("TEAM STATUS ERROR:", error);

      return res.status(500).json({
        status: false,
        message: "Unable to update team member status.",
      });
    }
  }
);

// =====================================================
// TEAM MANAGEMENT - DELETE MEMBER
// DELETE /admin/team/members/:id
// =====================================================

router.delete(
  "/team/members/:id",
  teamAuth,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!/^\d+$/.test(id)) {
        return res.status(400).json({
          status: false,
          message: "Invalid member ID.",
        });
      }

      if (Number(id) === Number(req.admin.id)) {
        return res.status(400).json({
          status: false,
          message: "You cannot delete your own account.",
        });
      }

      const [result] = await pool.query(
        `DELETE FROM users
         WHERE id = ?
         AND role IN ('Admin', 'Sub Admin', 'Staff')`,
        [id]
      );

      if (!result.affectedRows) {
        return res.status(404).json({
          status: false,
          message: "Team member not found.",
        });
      }

      return res.json({
        status: true,
        message: "Team member deleted successfully.",
      });
    } catch (error) {
      console.error("DELETE TEAM MEMBER ERROR:", error);

      return res.status(500).json({
        status: false,
        message: "Unable to delete team member.",
      });
    }
  }
);

module.exports = router;
module.exports.teamRouter = teamRouter;
