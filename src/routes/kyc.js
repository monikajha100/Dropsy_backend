const express = require("express");
const router = express.Router();
const pool = require("./pool");

// ======================================================
// GET ALL SELLERS' KYC DOCUMENTS
// GET /api/kyc/all
// ======================================================

router.get("/all", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        k.id,
        k.seller_id,
        k.document_type,
        k.document_number_masked,
        k.storage_path,
        k.original_filename,
        k.mime_type,
        k.document_status,
        k.rejection_reason,
        k.reviewed_at,
        k.created_at,
        s.fullName,
        s.email,
        s.mobile,
        s.enrollmentNumber
      FROM seller_kyc_documents k
      LEFT JOIN sellers s
        ON s.id = k.seller_id
      ORDER BY k.created_at DESC
    `);

    const data = rows.map((row) => {
      const storagePath = String(row.storage_path || "").replace(/^\/+/, "");

      return {
        ...row,
        status: row.document_status,
        kyc_status: row.document_status,
        document_url: storagePath
          ? `${req.protocol}://${req.get("host")}/${storagePath}`
          : "",
      };
    });

    return res.status(200).json({
      success: true,
      count: data.length,
      data,
      kycs: data,
    });
  } catch (error) {
    console.error("FETCH ALL KYC ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch KYC documents.",
      error: error.message,
    });
  }
});

// ======================================================
// GET KYC DOCUMENTS OF ONE SELLER
// GET /api/kyc/seller/:sellerId
// ======================================================

router.get("/seller/:sellerId", async (req, res) => {
  try {
    const sellerId = Number(req.params.sellerId);

    if (!Number.isInteger(sellerId) || sellerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid seller ID.",
      });
    }

    const [rows] = await pool.query(
      `
      SELECT
        id,
        seller_id,
        document_type,
        document_number_masked,
        storage_path,
        original_filename,
        mime_type,
        document_status,
        rejection_reason,
        reviewed_at,
        created_at
      FROM seller_kyc_documents
      WHERE seller_id = ?
      ORDER BY created_at DESC
      `,
      [sellerId]
    );

    const data = rows.map((row) => {
      const storagePath = String(row.storage_path || "").replace(/^\/+/, "");

      return {
        ...row,
        status: row.document_status,
        document_url: storagePath
          ? `${req.protocol}://${req.get("host")}/${storagePath}`
          : "",
      };
    });

    return res.status(200).json({
      success: true,
      count: data.length,
      data,
    });
  } catch (error) {
    console.error("FETCH SELLER KYC ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch seller KYC.",
      error: error.message,
    });
  }
});

// ======================================================
// UPDATE KYC DOCUMENT STATUS
// PUT /api/kyc/:id/status
// ======================================================

router.put("/:id/status", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status, rejection_reason } = req.body || {};

    const allowedStatuses = [
      "pending",
      "submitted",
      "approved",
      "rejected",
    ];

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid KYC document ID.",
      });
    }

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid KYC status.",
      });
    }

    if (
      status === "rejected" &&
      !String(rejection_reason || "").trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Rejection reason is required.",
      });
    }

    const [result] = await pool.query(
      `
      UPDATE seller_kyc_documents
      SET
        document_status = ?,
        rejection_reason = ?,
        reviewed_at = NOW()
      WHERE id = ?
      `,
      [
        status,
        status === "rejected"
          ? String(rejection_reason).trim()
          : null,
        id,
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "KYC document not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "KYC status updated successfully.",
    });
  } catch (error) {
    console.error("UPDATE KYC STATUS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to update KYC status.",
      error: error.message,
    });
  }
});

module.exports = router;