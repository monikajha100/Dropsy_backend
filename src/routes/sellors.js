const express = require("express");
const router = express.Router();
const pool = require("./pool");

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

const SESSION_DAYS = 7;
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const UPLOAD_DIR = path.resolve(__dirname, "../../uploads");

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ======================================================
// ENROLLMENT NUMBER
// ======================================================

function generateEnrollmentNumber(serialNumber) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).formatToParts(new Date());

  const dd = parts.find((p) => p.type === "day").value;
  const mm = parts.find((p) => p.type === "month").value;
  const yyyy = parts.find((p) => p.type === "year").value;

  return `DS${dd}${mm}${yyyy}_${serialNumber}`;
}

// ======================================================
// SESSION HELPERS
// ======================================================

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);
  return match ? match[1] : null;
}

async function authenticateSeller(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        status: false,
        message: "Please log in to continue.",
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
        message: "Session expired or invalid. Please log in again.",
      });
    }

    req.sellerId = sessions[0].seller_id;
    req.sessionId = sessions[0].id;
    req.sessionTokenHash = tokenHash;

    next();
  } catch (error) {
    console.error("SELLER AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to verify seller session.",
    });
  }
}

// ======================================================
// MULTER
// ======================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),

  filename: (req, file, cb) => {
    const extensions = {
      "image/jpeg": ".jpg",
      "image/png": ".png",
      "application/pdf": ".pdf",
    };

    const extension = extensions[file.mimetype];

    if (!extension) {
      return cb(new Error("Only JPG, PNG and PDF files are allowed."));
    }

    cb(null, `${crypto.randomUUID()}${extension}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "application/pdf",
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG and PDF files are allowed."));
    }

    cb(null, true);
  },
});

// ======================================================
// REGISTER
// POST /api/sellers/register
// ======================================================

router.post("/register", async (req, res) => {
  try {
    const fields = [
      "fullName",
      "mobile",
      "altMobile",
      "email",
      "whatsapp",
      "address",
      "city",
      "state",
      "pincode",
      "gstNumber",
    ];

    const data = {};

    for (const field of fields) {
      const value = req.body?.[field];
      data[field] = typeof value === "string" ? value.trim() : "";
    }

    data.email = data.email.toLowerCase();

    if (
      !data.fullName ||
      !data.mobile ||
      !data.email ||
      !data.address ||
      !data.city ||
      !data.state
    ) {
      return res.status(400).json({
        success: false,
        message: "Please fill all required fields.",
      });
    }

    if (!/^\d{10}$/.test(data.mobile)) {
      return res.status(400).json({
        success: false,
        message: "Mobile number must be exactly 10 digits.",
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(data.email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address.",
      });
    }

    if (data.pincode && !/^\d{6}$/.test(data.pincode)) {
      return res.status(400).json({
        success: false,
        message: "PIN code must be exactly 6 digits.",
      });
    }

    const [existing] = await pool.query(
      `SELECT id, mobile, email
       FROM sellers
       WHERE mobile = ? OR LOWER(email) = ?
       LIMIT 1`,
      [data.mobile, data.email]
    );

    if (existing.length) {
      return res.status(409).json({
        success: false,
        message:
          existing[0].mobile === data.mobile
            ? "This mobile number is already registered."
            : "This email address is already registered.",
      });
    }

    return res.json({
      success: true,
      message: "Details validated. Continue to payment.",
      sellerData: data,
    });
  } catch (error) {
    console.error("SELLER REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to validate seller registration.",
    });
  }
});

// ======================================================
// LOGIN
// POST /api/sellers/login
// ======================================================

router.post("/login", async (req, res) => {
  try {
    const { email, enrollmentNumber } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof enrollmentNumber !== "string" ||
      !email.trim() ||
      !enrollmentNumber.trim()
    ) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Email and enrollment number are required.",
      });
    }

    const [rows] = await pool.query(
      `SELECT *
       FROM sellers
       WHERE LOWER(email) = ?
         AND enrollmentNumber = ?
         AND payment_status = 'paid'
         AND enrollment_generated = 1
       LIMIT 1`,
      [email.trim().toLowerCase(), enrollmentNumber.trim()]
    );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        status: false,
        message: "Invalid login details or payment is incomplete.",
      });
    }

    const seller = rows[0];
    const rawToken = createSessionToken();
    const tokenHash = hashSessionToken(rawToken);

    await pool.query(
      `INSERT INTO seller_login_sessions
       (seller_id, session_token, ip_address, user_agent, expires_at, status)
       VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? DAY), 'active')`,
      [
        seller.id,
        tokenHash,
        req.ip || null,
        req.get("user-agent") || null,
        SESSION_DAYS,
      ]
    );

    return res.json({
      success: true,
      status: true,
      message: "Seller login successful.",
      token: rawToken,
      expiresInDays: SESSION_DAYS,
      seller,
    });
  } catch (error) {
    console.error("SELLER LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Server error while logging in.",
    });
  }
});

// ======================================================
// CURRENT SELLER PROFILE
// GET /api/sellers/me
// ======================================================

router.get("/me", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
        s.id AS seller_id,
        s.enrollmentNumber,
        s.fullName,
        s.mobile,
        s.altMobile,
        s.email,
        s.gstNumber,
        s.whatsapp,
        s.address,
        s.city,
        s.state,
        s.pincode,
        s.payment_status,
        s.created_at AS seller_created_at,
        p.user_type,
        p.address_line1,
        p.address_line2,
        p.city AS business_city,
        p.state AS business_state,
        p.country,
        p.pincode AS business_pincode,
        p.company_name,
        p.store_name,
        p.gstin,
        p.pan_number,
        p.bank_name,
        p.account_holder_name,
        p.account_number,
        p.ifsc,
        p.branch_name
       FROM sellers s
       LEFT JOIN seller_profiles p ON p.seller_id = s.id
       WHERE s.id = ?
       LIMIT 1`,
      [req.sellerId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        status: false,
        message: "Seller not found.",
      });
    }

    const seller = rows[0];

    seller.userType = seller.user_type;
    seller.address1 = seller.address_line1;
    seller.address2 = seller.address_line2;
    seller.businessCity = seller.business_city;
    seller.businessState = seller.business_state;
    seller.businessPincode = seller.business_pincode;
    seller.companyName = seller.company_name;
    seller.storeName = seller.store_name;
    seller.gstinNumber = seller.gstin;
    seller.pan = seller.pan_number;
    seller.bankName = seller.bank_name;
    seller.accountHolder = seller.account_holder_name;
    seller.accountNumber = seller.account_number;
    seller.ifscCode = seller.ifsc;
    seller.branchName = seller.branch_name;

    return res.json({
      success: true,
      status: true,
      seller,
    });
  } catch (error) {
    console.error("SELLER PROFILE FETCH ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to fetch seller profile.",
    });
  }
});

// ======================================================
// SAVE BUSINESS PROFILE
// PUT /api/sellers/profile
// ======================================================

router.put("/profile", authenticateSeller, async (req, res) => {
  let connection;

  try {
    const fieldMap = {
      user_type: "user_type",
      userType: "user_type",
      address_line1: "address_line1",
      address1: "address_line1",
      address_line2: "address_line2",
      address2: "address_line2",
      city: "city",
      business_city: "city",
      businessCity: "city",
      state: "state",
      business_state: "state",
      businessState: "state",
      country: "country",
      pincode: "pincode",
      business_pincode: "pincode",
      businessPincode: "pincode",
      company_name: "company_name",
      companyName: "company_name",
      store_name: "store_name",
      storeName: "store_name",
      gstin: "gstin",
      gstinNumber: "gstin",
      pan_number: "pan_number",
      pan: "pan_number",
      bank_name: "bank_name",
      bankName: "bank_name",
      account_holder_name: "account_holder_name",
      accountHolder: "account_holder_name",
      accountHolderName: "account_holder_name",
      account_number: "account_number",
      accountNumber: "account_number",
      ifsc: "ifsc",
      ifscCode: "ifsc",
      branch_name: "branch_name",
      branchName: "branch_name",
    };

    const updates = {};

    for (const [input, column] of Object.entries(fieldMap)) {
      if (Object.prototype.hasOwnProperty.call(req.body || {}, input)) {
        const value = req.body[input];

        if (value !== null && typeof value !== "string") {
          return res.status(400).json({
            success: false,
            status: false,
            message: `Invalid value for ${input}.`,
          });
        }

        if (!Object.prototype.hasOwnProperty.call(updates, column)) {
          updates[column] =
            typeof value === "string" ? value.trim() || null : null;
        }
      }
    }

    if (!Object.keys(updates).length) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "No business profile fields provided.",
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [existing] = await connection.query(
      `SELECT id FROM seller_profiles
       WHERE seller_id = ? LIMIT 1 FOR UPDATE`,
      [req.sellerId]
    );

    const fields = Object.keys(updates);

    if (existing.length) {
      const setClause = fields
        .map((field) => `\`${field}\` = ?`)
        .join(", ");

      await connection.query(
        `UPDATE seller_profiles
         SET ${setClause}, updated_at = CURRENT_TIMESTAMP
         WHERE seller_id = ?`,
        [...fields.map((field) => updates[field]), req.sellerId]
      );
    } else {
      const columns = ["seller_id", ...fields]
        .map((field) => `\`${field}\``)
        .join(", ");

      const placeholders = ["seller_id", ...fields]
        .map(() => "?")
        .join(", ");

      await connection.query(
        `INSERT INTO seller_profiles (${columns})
         VALUES (${placeholders})`,
        [req.sellerId, ...fields.map((field) => updates[field])]
      );
    }

    await connection.commit();

    return res.json({
      success: true,
      status: true,
      message: "Business profile saved successfully.",
    });
  } catch (error) {
    if (connection) await connection.rollback();

    console.error("BUSINESS PROFILE SAVE ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to save business profile.",
    });
  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// CURRENT SELLER KYC
// GET /api/sellers/kyc
// ======================================================

router.get("/kyc", authenticateSeller, async (req, res) => {
  try {
    const [documents] = await pool.query(
      `SELECT
        id, document_type, document_number_masked,
        original_filename, mime_type, document_status,
        rejection_reason, reviewed_at, created_at, updated_at
       FROM seller_kyc_documents
       WHERE seller_id = ?
       ORDER BY id DESC`,
      [req.sellerId]
    );

    return res.json({
      success: true,
      status: true,
      documents,
    });
  } catch (error) {
    console.error("SELLER KYC FETCH ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to fetch KYC documents.",
    });
  }
});

// ======================================================
// UPLOAD KYC
// POST /api/sellers/kyc/upload
// ======================================================

router.post(
  "/kyc/upload",
  authenticateSeller,
  (req, res, next) => {
    upload.single("document")(req, res, (error) => {
      if (error) {
        return res.status(400).json({
          success: false,
          status: false,
          message: error.message || "Document upload failed.",
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const allowedDocuments = [
        "gst",
        "photo",
        "pan",
        "aadhaar",
        "bankProof",
      ];

      const documentType = req.body.document_type;

      if (!allowedDocuments.includes(documentType)) {
        if (req.file) fs.unlink(req.file.path, () => {});

        return res.status(400).json({
          success: false,
          status: false,
          message: "Invalid KYC document type.",
        });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          status: false,
          message: "Please select a document.",
        });
      }

      const rawNumber =
        typeof req.body.document_number === "string"
          ? req.body.document_number.trim()
          : "";

      const maskedNumber = rawNumber
        ? `****${rawNumber.slice(-4)}`
        : null;

      await pool.query(
        `INSERT INTO seller_kyc_documents (
          seller_id,
          document_type,
          document_number_masked,
          storage_path,
          original_filename,
          mime_type,
          document_status,
          rejection_reason,
          reviewed_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, NULL)`,
        [
          req.sellerId,
          documentType,
          maskedNumber,
          `uploads/${req.file.filename}`,
          path.basename(req.file.originalname),
          req.file.mimetype,
        ]
      );

      return res.status(201).json({
        success: true,
        status: true,
        message: "KYC document uploaded for review.",
      });
    } catch (error) {
      if (req.file) fs.unlink(req.file.path, () => {});

      console.error("SELLER KYC UPLOAD ERROR:", error);

      return res.status(500).json({
        success: false,
        status: false,
        message: "Unable to save KYC document.",
      });
    }
  }
);

// ======================================================
// LOGOUT
// POST /api/sellers/logout
// ======================================================

router.post("/logout", authenticateSeller, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM seller_login_sessions
       WHERE id = ? AND seller_id = ?`,
      [req.sessionId, req.sellerId]
    );

    return res.json({
      success: true,
      status: true,
      message: "Logged out successfully.",
    });
  } catch (error) {
    console.error("SELLER LOGOUT ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Unable to log out.",
    });
  }
});

// ======================================================
// GET ALL SELLERS
// GET /api/sellers/all
// ======================================================

router.get("/all", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
        id, enrollmentNumber, fullName, mobile, altMobile,
        email, gstNumber, whatsapp, address, city, state,
        pincode, payment_status, enrollment_generated,
        created_at, updated_at
       FROM sellers
       ORDER BY id DESC`
    );

    return res.json({
      success: true,
      count: rows.length,
      sellers: rows,
    });
  } catch (error) {
    console.error("FETCH SELLERS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch sellers.",
    });
  }
});

// ======================================================
// PAYMENT SUCCESS
// POST /api/sellers/payment-success
// ======================================================

router.post("/payment-success", async (req, res) => {
  let connection;

  try {
    const { sellerId, packageId, packageName, amount } = req.body || {};

    if (!Number.isInteger(Number(sellerId)) || Number(sellerId) < 1) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "A valid Seller ID is required.",
      });
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS seller_enrollment_sequence (
        id TINYINT NOT NULL PRIMARY KEY,
        last_serial BIGINT UNSIGNED NOT NULL
      ) ENGINE=InnoDB
    `);

    await pool.query(`
      INSERT IGNORE INTO seller_enrollment_sequence (id, last_serial)
      VALUES (1, 100)
    `);

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [sellers] = await connection.query(
      `SELECT id, enrollmentNumber, email, payment_status,
              enrollment_generated
       FROM sellers
       WHERE id = ?
       LIMIT 1 FOR UPDATE`,
      [Number(sellerId)]
    );

    if (!sellers.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        status: false,
        message: "Seller not found.",
      });
    }

    const seller = sellers[0];

    if (
      seller.payment_status === "paid" &&
      Number(seller.enrollment_generated) === 1 &&
      seller.enrollmentNumber
    ) {
      await connection.commit();

      return res.json({
        success: true,
        status: true,
        message: "Enrollment already generated.",
        sellerId: seller.id,
        enrollmentNumber: seller.enrollmentNumber,
        payment_status: "paid",
        enrollment_generated: 1,
      });
    }

    const [sequenceRows] = await connection.query(
      `SELECT last_serial
       FROM seller_enrollment_sequence
       WHERE id = 1 FOR UPDATE`
    );

    if (!sequenceRows.length) {
      throw new Error("Enrollment sequence counter not initialized.");
    }

    const nextSerial = Number(sequenceRows[0].last_serial) + 1;

    await connection.query(
      `UPDATE seller_enrollment_sequence
       SET last_serial = ?
       WHERE id = 1`,
      [nextSerial]
    );

    const enrollmentNumber = generateEnrollmentNumber(nextSerial);

    await connection.query(
      `UPDATE sellers
       SET enrollmentNumber = ?,
           payment_status = 'paid',
           enrollment_generated = 1,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [enrollmentNumber, seller.id]
    );

    await connection.commit();

    return res.json({
      success: true,
      status: true,
      message: "Enrollment number generated successfully.",
      sellerId: seller.id,
      enrollmentNumber,
      payment_status: "paid",
      enrollment_generated: 1,
      package: {
        id: packageId || null,
        name: packageName || null,
        amount: amount ?? null,
      },
      email: seller.email,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("PAYMENT ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("SELLER PAYMENT ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Server error while processing payment.",
    });
  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// ADMIN CREATE SELLER
// POST /api/sellers/admin/create
// Inserts a seller directly (payment pending, no enrollment
// number until /payment-success is called).
// ======================================================


// ======================================================
// ADMIN CREATE SELLER
// POST /api/sellers/admin/create
// Enrollment generated for BOTH paid and pending sellers
// ======================================================

router.post("/admin/create", async (req, res) => {
  let connection;

  try {
    const fields = [
      "fullName",
      "mobile",
      "altMobile",
      "email",
      "gstNumber",
      "whatsapp",
      "address",
      "city",
      "state",
      "pincode",
    ];

    const data = {};

    for (const field of fields) {
      const value = req.body?.[field];
      data[field] = typeof value === "string" ? value.trim() : "";
    }

    data.email = data.email.toLowerCase();

    // Validate required fields
    if (
      !data.fullName ||
      !data.mobile ||
      !data.email ||
      !data.address ||
      !data.city ||
      !data.state
    ) {
      return res.status(400).json({
        success: false,
        message: "Please fill all required fields.",
      });
    }

    if (!/^\d{10}$/.test(data.mobile)) {
      return res.status(400).json({
        success: false,
        message: "Mobile number must be exactly 10 digits.",
      });
    }

    if (data.altMobile && !/^\d{10}$/.test(data.altMobile)) {
      return res.status(400).json({
        success: false,
        message: "Alternate mobile must be 10 digits.",
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(data.email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address.",
      });
    }

    if (data.pincode && !/^\d{6}$/.test(data.pincode)) {
      return res.status(400).json({
        success: false,
        message: "PIN code must be exactly 6 digits.",
      });
    }

    // Only the admin's explicit cash confirmation marks payment paid.
    const paymentReceived = req.body?.payment_received === true;

    const paymentStatus = paymentReceived ? "paid" : "pending";
    const paymentMethod = paymentReceived ? "cash" : null;

    // Ensure enrollment sequence table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS seller_enrollment_sequence (
        id TINYINT NOT NULL PRIMARY KEY,
        last_serial BIGINT UNSIGNED NOT NULL
      ) ENGINE=InnoDB
    `);

    await pool.query(`
      INSERT IGNORE INTO seller_enrollment_sequence (id, last_serial)
      VALUES (1, 100)
    `);

    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Check duplicate mobile/email
    const [existing] = await connection.query(
      `SELECT id, mobile, email
       FROM sellers
       WHERE mobile = ? OR LOWER(email) = ?
       LIMIT 1`,
      [data.mobile, data.email]
    );

    if (existing.length) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          existing[0].mobile === data.mobile
            ? "This mobile number is already registered."
            : "This email address is already registered.",
      });
    }

    // Lock sequence row to prevent duplicate enrollment numbers
    const [sequenceRows] = await connection.query(
      `SELECT last_serial
       FROM seller_enrollment_sequence
       WHERE id = 1
       FOR UPDATE`
    );

    if (!sequenceRows.length) {
      throw new Error("Enrollment sequence counter not initialized.");
    }

    const nextSerial = Number(sequenceRows[0].last_serial) + 1;

    await connection.query(
      `UPDATE seller_enrollment_sequence
       SET last_serial = ?
       WHERE id = 1`,
      [nextSerial]
    );

    // Generate enrollment for paid AND pending sellers
    const enrollmentNumber = generateEnrollmentNumber(nextSerial);

    // Check whether payment_method column exists in this database
    const [paymentMethodColumns] = await connection.query(
      `SHOW COLUMNS FROM sellers LIKE 'payment_method'`
    );

    let insertColumns = [
      "fullName",
      "mobile",
      "altMobile",
      "email",
      "gstNumber",
      "whatsapp",
      "address",
      "city",
      "state",
      "pincode",
      "enrollmentNumber",
      "payment_status",
      "enrollment_generated",
    ];

    let insertValues = [
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
      enrollmentNumber,
      paymentStatus,
      1,
    ];

    // Save cash payment method if the column exists
    if (paymentMethodColumns.length) {
      insertColumns.push("payment_method");
      insertValues.push(paymentMethod);
    }

    const placeholders = insertColumns.map(() => "?").join(", ");
    const columnNames = insertColumns
      .map((column) => `\`${column}\``)
      .join(", ");

    const [result] = await connection.query(
      `INSERT INTO sellers (${columnNames})
       VALUES (${placeholders})`,
      insertValues
    );

    const sellerId = result.insertId;

    await connection.commit();

    return res.status(201).json({
      success: true,
      message: paymentReceived
        ? "Seller registered successfully. Cash payment received."
        : "Seller registered successfully. Payment is pending.",
      sellerId,
      enrollmentNumber,
      fullName: data.fullName,
      email: data.email,
      payment_status: paymentStatus,
      payment_method: paymentMethod,
      enrollment_generated: 1,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("ADMIN CREATE ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("ADMIN CREATE SELLER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create seller.",
      error: error.message,
    });
  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// ADMIN: ALL KYC DOCUMENTS + BUSINESS PROFILES
// GET /api/sellers/admin/kyc
// ======================================================

router.get("/admin/kyc", async (req, res) => {
  try {
    const [documents] = await pool.query(
      `SELECT
        id, seller_id, document_type, document_number_masked,
        original_filename, mime_type, document_status,
        rejection_reason, reviewed_at, created_at, updated_at
       FROM seller_kyc_documents
       ORDER BY id DESC`
    );

    const [profiles] = await pool.query(
      `SELECT
        seller_id, user_type, address_line1, address_line2, city, state,
        country, pincode, company_name, store_name, gstin, pan_number,
        bank_name, account_holder_name, account_number, ifsc, branch_name
       FROM seller_profiles`
    );

    return res.json({
      success: true,
      documents,
      profiles,
    });
  } catch (error) {
    console.error("ADMIN KYC FETCH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch KYC data.",
    });
  }
});

// ======================================================
// ADMIN: VIEW A KYC FILE
// GET /api/sellers/admin/kyc/file/:docId
// ======================================================

router.get("/admin/kyc/file/:docId", async (req, res) => {
  try {
    const docId = Number(req.params.docId);

    if (!Number.isInteger(docId) || docId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid document ID.",
      });
    }

    const [rows] = await pool.query(
      `SELECT storage_path, mime_type
       FROM seller_kyc_documents
       WHERE id = ?
       LIMIT 1`,
      [docId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Document not found.",
      });
    }

    const filename = path.basename(String(rows[0].storage_path || ""));
    const filePath = path.join(UPLOAD_DIR, filename);

    if (!filename || !fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        message: "File is missing on the server.",
      });
    }

    res.setHeader("Cache-Control", "private, max-age=300");
    if (rows[0].mime_type) res.type(rows[0].mime_type);

    return res.sendFile(filePath);
  } catch (error) {
    console.error("ADMIN KYC FILE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to open file.",
    });
  }
});

// ======================================================
// ADMIN: APPROVE / REJECT A KYC DOCUMENT
// PUT /api/sellers/admin/kyc/:docId/review
// body: { status: "approved" | "rejected", reason? }
// ======================================================

router.put("/admin/kyc/:docId/review", async (req, res) => {
  try {
    const docId = Number(req.params.docId);
    const status = req.body?.status;
    const reason =
      typeof req.body?.reason === "string" ? req.body.reason.trim() : "";

    if (!Number.isInteger(docId) || docId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid document ID.",
      });
    }

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be approved or rejected.",
      });
    }

    if (status === "rejected" && !reason) {
      return res.status(400).json({
        success: false,
        message: "Rejection reason is required.",
      });
    }

    const [result] = await pool.query(
      `UPDATE seller_kyc_documents
       SET document_status = ?,
           rejection_reason = ?,
           reviewed_at = NOW(),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [status, status === "rejected" ? reason : null, docId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Document not found.",
      });
    }

    return res.json({
      success: true,
      message: `Document ${status}.`,
    });
  } catch (error) {
    console.error("ADMIN KYC REVIEW ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to update document.",
    });
  }
});

// ======================================================
// GET SINGLE SELLER
// GET /api/sellers/:id
// ======================================================

router.get("/:id", async (req, res) => {
  try {
    const sellerId = Number(req.params.id);

    if (!Number.isInteger(sellerId) || sellerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid seller ID.",
      });
    }

    const [rows] = await pool.query(
      `SELECT
        id, enrollmentNumber, fullName, mobile, altMobile,
        email, gstNumber, whatsapp, address, city, state,
        pincode, payment_status, enrollment_generated,
        created_at, updated_at
       FROM sellers
       WHERE id = ?
       LIMIT 1`,
      [sellerId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Seller not found.",
      });
    }

    return res.json({
      success: true,
      seller: rows[0],
    });
  } catch (error) {
    console.error("GET SELLER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch seller.",
    });
  }
});

// ======================================================
// ADMIN EDIT SELLER
// PUT /api/sellers/:id
// ======================================================

router.put("/:id", async (req, res) => {
  try {
    const sellerId = Number(req.params.id);

    if (!Number.isInteger(sellerId) || sellerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid seller ID.",
      });
    }

    const allowedFields = [
      "fullName",
      "mobile",
      "altMobile",
      "email",
      "gstNumber",
      "whatsapp",
      "address",
      "city",
      "state",
      "pincode",
    ];

    const updates = {};

    for (const field of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
        const value = req.body[field];

        if (value !== null && typeof value !== "string") {
          return res.status(400).json({
            success: false,
            message: `Invalid ${field}.`,
          });
        }

        updates[field] =
          typeof value === "string" ? value.trim() : "";
      }
    }

    if (!Object.keys(updates).length) {
      return res.status(400).json({
        success: false,
        message: "No seller details provided.",
      });
    }

    if (updates.fullName !== undefined && !updates.fullName) {
      return res.status(400).json({
        success: false,
        message: "Seller name is required.",
      });
    }

    if (updates.mobile !== undefined && !/^\d{10}$/.test(updates.mobile)) {
      return res.status(400).json({
        success: false,
        message: "Mobile must be 10 digits.",
      });
    }

    if (
      updates.altMobile &&
      !/^\d{10}$/.test(updates.altMobile)
    ) {
      return res.status(400).json({
        success: false,
        message: "Alternate mobile must be 10 digits.",
      });
    }

    if (updates.email !== undefined) {
      updates.email = updates.email.toLowerCase();

      if (!/^\S+@\S+\.\S+$/.test(updates.email)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email address.",
        });
      }
    }

    if (updates.pincode && !/^\d{6}$/.test(updates.pincode)) {
      return res.status(400).json({
        success: false,
        message: "PIN code must be 6 digits.",
      });
    }

    const [seller] = await pool.query(
      "SELECT id FROM sellers WHERE id = ? LIMIT 1",
      [sellerId]
    );

    if (!seller.length) {
      return res.status(404).json({
        success: false,
        message: "Seller not found.",
      });
    }

    const duplicateConditions = [];
    const duplicateValues = [];

    if (updates.mobile !== undefined) {
      duplicateConditions.push("mobile = ?");
      duplicateValues.push(updates.mobile);
    }

    if (updates.email !== undefined) {
      duplicateConditions.push("LOWER(email) = ?");
      duplicateValues.push(updates.email);
    }

    if (duplicateConditions.length) {
      const [duplicate] = await pool.query(
        `SELECT id FROM sellers
         WHERE id != ?
           AND (${duplicateConditions.join(" OR ")})
         LIMIT 1`,
        [sellerId, ...duplicateValues]
      );

      if (duplicate.length) {
        return res.status(409).json({
          success: false,
          message: "Mobile number or email already belongs to another seller.",
        });
      }
    }

    const fields = Object.keys(updates);
    const setClause = fields
      .map((field) => `\`${field}\` = ?`)
      .join(", ");

    await pool.query(
      `UPDATE sellers
       SET ${setClause}, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [...fields.map((field) => updates[field]), sellerId]
    );

    const [updated] = await pool.query(
      "SELECT * FROM sellers WHERE id = ? LIMIT 1",
      [sellerId]
    );

    return res.json({
      success: true,
      message: "Seller updated successfully.",
      seller: updated[0],
    });
  } catch (error) {
    console.error("ADMIN EDIT SELLER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to update seller.",
    });
  }
});

// ======================================================
// DELETE SELLER
// DELETE /api/sellers/:id
// Preserves orders, payments and financial history.
// ======================================================

router.delete("/:id", async (req, res) => {
  let connection;

  try {
    const sellerId = Number(req.params.id);

    if (!Number.isInteger(sellerId) || sellerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid seller ID.",
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [sellers] = await connection.query(
      `SELECT id FROM sellers
       WHERE id = ?
       LIMIT 1 FOR UPDATE`,
      [sellerId]
    );

    if (!sellers.length) {
      await connection.rollback();

      return res.status(404).json({
        success: false,
        message: "Seller not found.",
      });
    }

    // Tables whose records can be removed with the seller.
    const removableTables = [
      "seller_login_sessions",
      "seller_profiles",
      "seller_kyc_documents",
    ];

    // Discover tables with seller_id references.
    const [references] = await connection.query(
      `SELECT TABLE_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND COLUMN_NAME = 'seller_id'`
    );

    const blockedTables = [];

    for (const item of references) {
      const tableName = item.TABLE_NAME;

      if (
        tableName === "sellers" ||
        removableTables.includes(tableName)
      ) {
        continue;
      }

      // Table name is read from INFORMATION_SCHEMA, not request input.
      const safeName = tableName.replace(/`/g, "``");

      const [counts] = await connection.query(
        `SELECT COUNT(*) AS total
         FROM \`${safeName}\`
         WHERE seller_id = ?`,
        [sellerId]
      );

      if (Number(counts[0].total) > 0) {
        blockedTables.push(tableName);
      }
    }

    if (blockedTables.length) {
      await connection.rollback();

      return res.status(409).json({
        success: false,
        message:
          "Seller has linked business records. Delete is blocked to preserve history.",
        relatedTables: blockedTables,
      });
    }

    // Remove KYC files after successful DB transaction only.
    const [documents] = await connection.query(
      `SELECT storage_path
       FROM seller_kyc_documents
       WHERE seller_id = ?`,
      [sellerId]
    );

    await connection.query(
      "DELETE FROM seller_login_sessions WHERE seller_id = ?",
      [sellerId]
    );

    await connection.query(
      "DELETE FROM seller_profiles WHERE seller_id = ?",
      [sellerId]
    );

    await connection.query(
      "DELETE FROM seller_kyc_documents WHERE seller_id = ?",
      [sellerId]
    );

    await connection.query(
      "DELETE FROM sellers WHERE id = ?",
      [sellerId]
    );

    await connection.commit();

    for (const document of documents) {
      const storedPath = String(document.storage_path || "");
      const filename = path.basename(storedPath);
      const filePath = path.join(UPLOAD_DIR, filename);

      if (filename && fs.existsSync(filePath)) {
        fs.unlink(filePath, (error) => {
          if (error) console.error("KYC FILE DELETE ERROR:", error);
        });
      }
    }

    return res.json({
      success: true,
      message: "Seller deleted successfully.",
      sellerId,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("SELLER DELETE ROLLBACK ERROR:", rollbackError);
      }
    }

    console.error("DELETE SELLER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to delete seller.",
    });
  } finally {
    if (connection) connection.release();
  }
});

module.exports = router;