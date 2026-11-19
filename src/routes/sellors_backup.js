
const express = require("express");
const router = express.Router();
const pool = require("./pool");

// ======================================================
// GENERATE UNIQUE ENROLLMENT NUMBER
// ======================================================

function generateEnrollmentNumber() {
  const now = new Date();

  const dd = String(now.getDate()).padStart(2, "0");
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const yyyy = now.getFullYear();
  const uniqueCode = Math.floor(100 + Math.random() * 900);

  return `D${dd}${mm}${yyyy}${uniqueCode}`;
}

// ======================================================
// SELLER REGISTER
// POST /api/sellers/register
// ======================================================

router.post("/register", async (req, res) => {
  try {
    const {
      fullName,
      mobile,
      altMobile,
      email,
      whatsapp,
      address,
      city,
      state,
      pincode,
    } = req.body;

    if (
      !fullName?.trim() ||
      !mobile?.trim() ||
      !email?.trim() ||
      !address?.trim() ||
      !city?.trim() ||
      !state?.trim()
    ) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Please fill all required fields.",
      });
    }

    const cleanFullName = fullName.trim();
    const cleanMobile = mobile.trim();
    const cleanEmail = email.trim().toLowerCase();
    const cleanAddress = address.trim();
    const cleanCity = city.trim();
    const cleanState = state.trim();

    const cleanAltMobile = altMobile?.trim() || null;
    const cleanWhatsapp = whatsapp?.trim() || null;
    const cleanPincode = pincode?.trim() || null;

    if (!/^\d{10}$/.test(cleanMobile)) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Mobile number must be exactly 10 digits.",
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Please enter a valid email address.",
      });
    }

    if (cleanPincode && !/^\d{6}$/.test(cleanPincode)) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "PIN code must be exactly 6 digits.",
      });
    }

    const [existing] = await pool.query(
      `SELECT id, mobile, email
       FROM sellers
       WHERE mobile = ? OR email = ?
       LIMIT 1`,
      [cleanMobile, cleanEmail]
    );

    if (existing.length) {
      return res.status(409).json({
        success: false,
        status: false,
        message:
          existing[0].mobile === cleanMobile
            ? "This mobile number is already registered."
            : "This email address is already registered.",
      });
    }

    const [result] = await pool.query(
      `INSERT INTO sellers (
        enrollmentNumber,
        fullName,
        mobile,
        altMobile,
        email,
        whatsapp,
        address,
        city,
        state,
        pincode,
        payment_status,
        enrollment_generated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        null,
        cleanFullName,
        cleanMobile,
        cleanAltMobile,
        cleanEmail,
        cleanWhatsapp,
        cleanAddress,
        cleanCity,
        cleanState,
        cleanPincode,
        "pending",
        0,
      ]
    );

    const [saved] = await pool.query(
      `SELECT id, fullName, mobile, email, payment_status,
              enrollment_generated, created_at
       FROM sellers WHERE id = ? LIMIT 1`,
      [result.insertId]
    );

    return res.status(201).json({
      success: true,
      status: true,
      message: "Registration successful. Please complete payment.",
      sellerId: result.insertId,
      seller: saved[0],
    });
  } catch (error) {
    console.error("SELLER REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Server error while registering seller.",
    });
  }
});

// ======================================================
// SELLER LOGIN
// POST /api/sellers/login
// Email + Enrollment Number
// ======================================================

router.post("/login", async (req, res) => {
  try {
    const { email, enrollmentNumber } = req.body;

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

    const cleanEmail = email.trim().toLowerCase();
    const cleanEnrollment = enrollmentNumber.trim();

    const [rows] = await pool.query(
      `SELECT
        id,
        enrollmentNumber,
        fullName,
        mobile,
        altMobile,
        email,
        whatsapp,
        address,
        city,
        state,
        pincode,
        payment_status,
        enrollment_generated,
        created_at,
        updated_at
      FROM sellers
      WHERE LOWER(email) = ?
        AND enrollmentNumber = ?
        AND payment_status = 'paid'
        AND enrollment_generated = 1
      LIMIT 1`,
      [cleanEmail, cleanEnrollment]
    );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        status: false,
        message:
          "Invalid email or enrollment number, or payment is not completed.",
      });
    }

    const seller = rows[0];

    return res.status(200).json({
      success: true,
      status: true,
      message: "Seller login successful.",
      seller,
    });
  } catch (error) {
    console.error("SELLER LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Server error while logging in seller.",
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
        id,
        enrollmentNumber,
        fullName,
        mobile,
        altMobile,
        email,
        whatsapp,
        address,
        city,
        state,
        pincode,
        payment_status,
        enrollment_generated,
        created_at,
        updated_at
      FROM sellers
      ORDER BY id DESC`
    );

    return res.status(200).json({
      success: true,
      status: true,
      count: rows.length,
      sellers: rows,
    });
  } catch (error) {
    console.error("FETCH SELLERS ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Server error while fetching sellers.",
    });
  }
});

// ======================================================
// PAYMENT SUCCESS
// POST /api/sellers/payment-success
// ======================================================

router.post("/payment-success", async (req, res) => {
  try {
    const { sellerId, packageId, packageName, amount, email } = req.body;

    if (!sellerId) {
      return res.status(400).json({
        success: false,
        status: false,
        message: "Seller ID is required.",
      });
    }

    const [sellers] = await pool.query(
      `SELECT id, enrollmentNumber, fullName, email,
              payment_status, enrollment_generated
       FROM sellers
       WHERE id = ?
       LIMIT 1`,
      [sellerId]
    );

    if (!sellers.length) {
      return res.status(404).json({
        success: false,
        status: false,
        message: "Seller not found.",
      });
    }

    const seller = sellers[0];

    // Return existing enrollment if already processed.
    if (
      seller.payment_status === "paid" &&
      Number(seller.enrollment_generated) === 1 &&
      seller.enrollmentNumber
    ) {
      return res.status(200).json({
        success: true,
        status: true,
        message: "Enrollment already generated.",
        sellerId: seller.id,
        enrollmentNumber: seller.enrollmentNumber,
        payment_status: "paid",
        enrollment_generated: 1,
      });
    }

    let enrollmentNumber;
    let isUnique = false;

    for (let attempt = 0; attempt < 20; attempt++) {
      const candidate = generateEnrollmentNumber();

      const [existing] = await pool.query(
        `SELECT id FROM sellers
         WHERE enrollmentNumber = ?
         LIMIT 1`,
        [candidate]
      );

      if (!existing.length) {
        enrollmentNumber = candidate;
        isUnique = true;
        break;
      }
    }

    if (!isUnique) {
      return res.status(500).json({
        success: false,
        status: false,
        message: "Could not generate a unique enrollment number.",
      });
    }

    await pool.query(
      `UPDATE sellers
       SET enrollmentNumber = ?,
           payment_status = 'paid',
           enrollment_generated = 1,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [enrollmentNumber, sellerId]
    );

    return res.status(200).json({
      success: true,
      status: true,
      message: "Enrollment number generated.",
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
    console.error("SELLER PAYMENT ERROR:", error);

    return res.status(500).json({
      success: false,
      status: false,
      message: "Server error while processing payment.",
    });
  }
});

module.exports = router;
