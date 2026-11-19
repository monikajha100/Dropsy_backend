
const express = require("express");
const router = express.Router();
const pool = require("./pool");

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const jwt = require("jsonwebtoken");

// ======================================================
// CONFIGURATION
// ======================================================

const JWT_SECRET =
    process.env.JWT_SECRET || "DROPSHY_ADMIN_SECRET_2026";

const UPLOAD_DIR = path.resolve(
    __dirname,
    "../../uploads/gst-ledger"
);

if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const MAX_FILE_SIZE = 5 * 1024 * 1024;

// ======================================================
// SELLER AUTHENTICATION
// ======================================================

function hashSessionToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

async function authenticateSeller(req, res, next) {
    try {
        const header = req.headers.authorization || "";
        const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);

        if (!match) {
            return res.status(401).json({
                success: false,
                message: "Seller login required.",
            });
        }

        const tokenHash = hashSessionToken(match[1]);

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
                message: "Seller session expired. Please login again.",
            });
        }

        req.sellerId = sessions[0].seller_id;
        next();

    } catch (error) {
        console.error("GST SELLER AUTH ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Seller authentication failed.",
        });
    }
}

// ======================================================
// ADMIN AUTHENTICATION
// ======================================================

function verifyAdmin(req, res, next) {
    try {
        const header = req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Admin token required.",
            });
        }

        const token = header.slice(7);
        const decoded = jwt.verify(token, JWT_SECRET);

        if (
            String(decoded.role || "").toLowerCase() !== "admin"
        ) {
            return res.status(403).json({
                success: false,
                message: "Admin access required.",
            });
        }

        req.admin = decoded;
        next();

    } catch (error) {
        console.error("GST ADMIN AUTH ERROR:", error.message);

        return res.status(401).json({
            success: false,
            message: "Invalid or expired admin token.",
        });
    }
}

// ======================================================
// PDF UPLOAD
// ======================================================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },

    filename: (req, file, cb) => {
        cb(null, `${crypto.randomUUID()}.pdf`);
    },
});

const upload = multer({
    storage,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1,
    },
    fileFilter: (req, file, cb) => {
        if (
            file.mimetype !== "application/pdf" ||
            path.extname(file.originalname).toLowerCase() !== ".pdf"
        ) {
            return cb(new Error("Only PDF invoices are allowed."));
        }

        cb(null, true);
    },
});

function handleInvoiceUpload(req, res, next) {
    upload.single("invoice_copy")(req, res, (error) => {
        if (error) {
            return res.status(400).json({
                success: false,
                message: error.message || "PDF upload failed.",
            });
        }

        next();
    });
}

// ======================================================
// GST CALCULATION
// ======================================================

function calculateGST(taxableAmount, gstRate, supplyType) {
    const taxable = Number(taxableAmount);
    const rate = Number(gstRate);

    let cgst = 0;
    let sgst = 0;
    let igst = 0;

    if (supplyType === "within") {
        cgst = taxable * (rate / 2) / 100;
        sgst = taxable * (rate / 2) / 100;
    } else {
        igst = taxable * rate / 100;
    }

    cgst = Number(cgst.toFixed(2));
    sgst = Number(sgst.toFixed(2));
    igst = Number(igst.toFixed(2));

    const totalGST = Number(
        (cgst + sgst + igst).toFixed(2)
    );

    const totalAmount = Number(
        (taxable + totalGST).toFixed(2)
    );

    return {
        cgst,
        sgst,
        igst,
        totalGST,
        totalAmount,
    };
}

// ======================================================
// VALIDATION
// ======================================================

function validateTransaction(body) {
    const {
        transaction_date,
        invoice_number,
        party_name,
        transaction_type,
        taxable_amount,
        gst_rate = 18,
        supply_type = "within",
        payment_status = "Unpaid",
        paid_amount = 0,
    } = body;

    if (
        !transaction_date ||
        !/^\d{4}-\d{2}-\d{2}$/.test(transaction_date)
    ) {
        return "Valid transaction date is required.";
    }

    if (
        typeof invoice_number !== "string" ||
        !invoice_number.trim()
    ) {
        return "Invoice number is required.";
    }

    if (
        typeof party_name !== "string" ||
        !party_name.trim()
    ) {
        return "Customer / Buyer name is required.";
    }

    if (!["Sales", "Purchase"].includes(transaction_type)) {
        return "Transaction type must be Sales or Purchase.";
    }

    if (
        taxable_amount === "" ||
        taxable_amount === undefined ||
        taxable_amount === null ||
        !Number.isFinite(Number(taxable_amount)) ||
        Number(taxable_amount) < 0
    ) {
        return "Valid taxable amount is required.";
    }

    if (
        !Number.isFinite(Number(gst_rate)) ||
        Number(gst_rate) < 0 ||
        Number(gst_rate) > 100
    ) {
        return "GST rate must be between 0 and 100.";
    }

    if (!["within", "outside"].includes(supply_type)) {
        return "Supply type must be within or outside.";
    }

    if (
        !["Paid", "Unpaid", "Partially Paid"].includes(payment_status)
    ) {
        return "Invalid payment status.";
    }

    if (
        !Number.isFinite(Number(paid_amount)) ||
        Number(paid_amount) < 0
    ) {
        return "Invalid paid amount.";
    }

    if (
        body.gstin &&
        !/^[0-9A-Z]{15}$/i.test(body.gstin.trim())
    ) {
        return "Please enter a valid 15-character GSTIN.";
    }

    return null;
}

// ======================================================
// PAYMENT DETAILS
// ======================================================

function getPaymentDetails(status, amount, invoiceTotal) {
    let paid = Number(amount || 0);

    if (status === "Paid") {
        paid = invoiceTotal;
    } else if (status === "Unpaid") {
        paid = 0;
    }

    paid = Number(paid.toFixed(2));

    if (paid > invoiceTotal) {
        throw new Error(
            "Paid amount cannot exceed invoice total."
        );
    }

    if (
        status === "Partially Paid" &&
        (paid <= 0 || paid >= invoiceTotal)
    ) {
        throw new Error(
            "Partially Paid amount must be greater than zero and less than invoice total."
        );
    }

    return paid;
}

// ======================================================
// COMMON QUERY FILTERS
// ======================================================

function addFilters(sql, params, query, prefix = "") {
    const { month, type, search } = query;

    if (month && /^\d{4}-\d{2}$/.test(month)) {
        sql += ` AND DATE_FORMAT(${prefix}transaction_date, '%Y-%m') = ?`;
        params.push(month);
    }

    if (type && ["Sales", "Purchase"].includes(type)) {
        sql += ` AND ${prefix}transaction_type = ?`;
        params.push(type);
    }

    if (search && String(search).trim()) {
        const value = `%${String(search).trim()}%`;

        sql += ` AND (
            ${prefix}invoice_number LIKE ?
            OR ${prefix}party_name LIKE ?
            OR ${prefix}gstin LIKE ?
            OR ${prefix}notes LIKE ?
        )`;

        params.push(value, value, value, value);
    }

    return sql;
}

// ======================================================
// SELLER GET GST LEDGER
// GET /api/gst-ledger
// ======================================================

router.get("/", authenticateSeller, async (req, res) => {
    try {
        let sql = `
            SELECT *
            FROM gst_ledger
            WHERE seller_id = ?
        `;

        const params = [req.sellerId];

        sql = addFilters(sql, params, req.query);

        sql += `
            ORDER BY transaction_date DESC, id DESC
        `;

        const [rows] = await pool.query(sql, params);

        return res.json({
            success: true,
            count: rows.length,
            data: rows,
        });

    } catch (error) {
        console.error("GST SELLER GET ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "GST Ledger fetch nahi ho saka.",
        });
    }
});

// ======================================================
// ADMIN GET ALL GST LEDGER
// GET /api/gst-ledger/admin
// ======================================================

router.get("/admin", verifyAdmin, async (req, res) => {
    try {
        const { seller_id } = req.query;

        let sql = `
            SELECT
                g.*,
                s.fullName AS seller_name,
                s.email AS seller_email,
                s.enrollmentNumber
            FROM gst_ledger g
            LEFT JOIN sellers s
                ON s.id = g.seller_id
            WHERE 1 = 1
        `;

        const params = [];

        if (
            seller_id &&
            Number.isInteger(Number(seller_id))
        ) {
            sql += " AND g.seller_id = ?";
            params.push(Number(seller_id));
        }

        sql = addFilters(sql, params, req.query, "g.");

        sql += `
            ORDER BY g.transaction_date DESC, g.id DESC
        `;

        const [rows] = await pool.query(sql, params);

        return res.json({
            success: true,
            count: rows.length,
            data: rows,
        });

    } catch (error) {
        console.error("GST ADMIN GET ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Admin GST Ledger fetch nahi ho saka.",
        });
    }
});

// ======================================================
// SELLER ADD GST TRANSACTION
// POST /api/gst-ledger
// ======================================================

router.post(
    "/",
    authenticateSeller,
    handleInvoiceUpload,
    async (req, res) => {
        try {
            const body = req.body || {};

            const validationError = validateTransaction(body);

            if (validationError) {
                if (req.file) {
                    fs.unlink(req.file.path, () => {});
                }

                return res.status(400).json({
                    success: false,
                    message: validationError,
                });
            }

            const taxable = Number(body.taxable_amount);
            const rate = Number(body.gst_rate ?? 18);
            const supply = body.supply_type || "within";

            const gst = calculateGST(
                taxable,
                rate,
                supply
            );

            const status = body.payment_status || "Unpaid";

            const paid = getPaymentDetails(
                status,
                body.paid_amount,
                gst.totalAmount
            );

            const invoiceCopy = req.file
                ? `uploads/gst-ledger/${req.file.filename}`
                : null;

            const gstin = body.gstin
                ? body.gstin.trim().toUpperCase()
                : null;

            const partyState = body.party_state
                ? body.party_state.trim()
                : null;

            const paymentMode = body.payment_mode
                ? body.payment_mode.trim()
                : null;

            const notes =
                typeof body.notes === "string"
                    ? body.notes.trim()
                    : "";

            const [result] = await pool.query(
                `INSERT INTO gst_ledger (
                    seller_id,
                    transaction_date,
                    invoice_number,
                    party_name,
                    transaction_type,
                    taxable_amount,
                    cgst,
                    sgst,
                    igst,
                    total_amount,
                    notes,
                    gstin,
                    party_state,
                    gst_rate,
                    supply_type,
                    payment_status,
                    paid_amount,
                    payment_mode,
                    invoice_copy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    req.sellerId,
                    body.transaction_date,
                    body.invoice_number.trim(),
                    body.party_name.trim(),
                    body.transaction_type,
                    taxable,
                    gst.cgst,
                    gst.sgst,
                    gst.igst,
                    gst.totalAmount,
                    notes,
                    gstin,
                    partyState,
                    rate,
                    supply,
                    status,
                    paid,
                    paymentMode,
                    invoiceCopy,
                ]
            );

            const [rows] = await pool.query(
                `SELECT *
                 FROM gst_ledger
                 WHERE id = ? AND seller_id = ?
                 LIMIT 1`,
                [result.insertId, req.sellerId]
            );

            return res.status(201).json({
                success: true,
                message: "GST transaction successfully save ho gaya.",
                data: rows[0],
            });

        } catch (error) {
            if (req.file) {
                fs.unlink(req.file.path, () => {});
            }

            console.error("GST POST ERROR:", error);

            return res.status(400).json({
                success: false,
                message: error.message ||
                    "GST transaction save nahi ho saka.",
            });
        }
    }
);

// ======================================================
// SELLER UPDATE GST TRANSACTION
// PUT /api/gst-ledger/:id
// ======================================================

router.put(
    "/:id",
    authenticateSeller,
    handleInvoiceUpload,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id < 1) {
                if (req.file) fs.unlink(req.file.path, () => {});

                return res.status(400).json({
                    success: false,
                    message: "Invalid transaction ID.",
                });
            }

            const [existing] = await pool.query(
                `SELECT id, invoice_copy
                 FROM gst_ledger
                 WHERE id = ? AND seller_id = ?
                 LIMIT 1`,
                [id, req.sellerId]
            );

            if (!existing.length) {
                if (req.file) fs.unlink(req.file.path, () => {});

                return res.status(404).json({
                    success: false,
                    message: "GST transaction not found.",
                });
            }

            const body = req.body || {};
            const validationError = validateTransaction(body);

            if (validationError) {
                if (req.file) fs.unlink(req.file.path, () => {});

                return res.status(400).json({
                    success: false,
                    message: validationError,
                });
            }

            const taxable = Number(body.taxable_amount);
            const rate = Number(body.gst_rate ?? 18);
            const supply = body.supply_type || "within";

            const gst = calculateGST(
                taxable,
                rate,
                supply
            );

            const status = body.payment_status || "Unpaid";

            const paid = getPaymentDetails(
                status,
                body.paid_amount,
                gst.totalAmount
            );

            const invoiceCopy = req.file
                ? `uploads/gst-ledger/${req.file.filename}`
                : existing[0].invoice_copy;

            await pool.query(
                `UPDATE gst_ledger SET
                    transaction_date = ?,
                    invoice_number = ?,
                    party_name = ?,
                    transaction_type = ?,
                    taxable_amount = ?,
                    cgst = ?,
                    sgst = ?,
                    igst = ?,
                    total_amount = ?,
                    notes = ?,
                    gstin = ?,
                    party_state = ?,
                    gst_rate = ?,
                    supply_type = ?,
                    payment_status = ?,
                    paid_amount = ?,
                    payment_mode = ?,
                    invoice_copy = ?,
                    updated_at = CURRENT_TIMESTAMP
                 WHERE id = ? AND seller_id = ?`,
                [
                    body.transaction_date,
                    body.invoice_number.trim(),
                    body.party_name.trim(),
                    body.transaction_type,
                    taxable,
                    gst.cgst,
                    gst.sgst,
                    gst.igst,
                    gst.totalAmount,
                    typeof body.notes === "string"
                        ? body.notes.trim()
                        : "",
                    body.gstin
                        ? body.gstin.trim().toUpperCase()
                        : null,
                    body.party_state
                        ? body.party_state.trim()
                        : null,
                    rate,
                    supply,
                    status,
                    paid,
                    body.payment_mode
                        ? body.payment_mode.trim()
                        : null,
                    invoiceCopy,
                    id,
                    req.sellerId,
                ]
            );

            const [rows] = await pool.query(
                `SELECT *
                 FROM gst_ledger
                 WHERE id = ? AND seller_id = ?
                 LIMIT 1`,
                [id, req.sellerId]
            );

            return res.json({
                success: true,
                message: "GST transaction updated successfully.",
                data: rows[0],
            });

        } catch (error) {
            if (req.file) {
                fs.unlink(req.file.path, () => {});
            }

            console.error("GST UPDATE ERROR:", error);

            return res.status(400).json({
                success: false,
                message: error.message ||
                    "GST transaction update nahi hua.",
            });
        }
    }
);

// ======================================================
// SELLER DELETE GST TRANSACTION
// DELETE /api/gst-ledger/:id
// ======================================================

router.delete("/:id", authenticateSeller, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                success: false,
                message: "Invalid transaction ID.",
            });
        }

        const [rows] = await pool.query(
            `SELECT invoice_copy
             FROM gst_ledger
             WHERE id = ? AND seller_id = ?
             LIMIT 1`,
            [id, req.sellerId]
        );

        if (!rows.length) {
            return res.status(404).json({
                success: false,
                message: "GST transaction not found.",
            });
        }

        await pool.query(
            `DELETE FROM gst_ledger
             WHERE id = ? AND seller_id = ?`,
            [id, req.sellerId]
        );

        if (rows[0].invoice_copy) {
            const filename = path.basename(
                rows[0].invoice_copy
            );

            const filePath = path.join(
                UPLOAD_DIR,
                filename
            );

            if (fs.existsSync(filePath)) {
                fs.unlink(filePath, () => {});
            }
        }

        return res.json({
            success: true,
            message: "GST transaction deleted successfully.",
        });

    } catch (error) {
        console.error("GST DELETE ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "GST transaction delete nahi hua.",
        });
    }
});

module.exports = router;
