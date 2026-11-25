
const express = require("express");
const router = express.Router();
const pool = require("./pool");

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");

// ======================================================
// CONFIGURATION
// ======================================================

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const MAX_MESSAGE_LENGTH = 500;

const UPLOAD_DIR = path.resolve(__dirname, "../../uploads");

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ======================================================
// SELLER AUTHENTICATION
// ======================================================

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);

  return match ? match[1] : null;
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function authenticateSeller(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
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
        message: "Session expired. Please log in again.",
      });
    }

    req.sellerId = sessions[0].seller_id;
    req.sessionId = sessions[0].id;

    next();
  } catch (error) {
    console.error("TICKET SELLER AUTH ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify seller session.",
    });
  }
}

// ======================================================
// FILE UPLOAD
// JPG / PNG / PDF - MAX 5 MB
// ======================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },

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
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
  },
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
// HELPERS
// ======================================================

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

function generateTicketNumber() {
  const date = new Date()
    .toISOString()
    .slice(0, 10)
    .replace(/-/g, "");

  const random = crypto.randomBytes(3)
    .toString("hex")
    .toUpperCase();

  return `TKT${date}${random}`;
}

function removeUploadedFile(file) {
  if (file?.path) {
    fs.unlink(file.path, () => {});
  }
}

// ======================================================
// CREATE TICKET
// POST /api/tickets
// ======================================================

router.post(
  "/",
  authenticateSeller,

  (req, res, next) => {
    upload.single("attachment")(req, res, (error) => {
      if (error) {
        return res.status(400).json({
          success: false,
          message: error.message || "Attachment upload failed.",
        });
      }

      next();
    });
  },

  async (req, res) => {
    let connection;
    let transactionStarted = false;

    try {
      const category = clean(req.body.category);

      const message = clean(
        req.body.message || req.body.description
      );

      const orderAwb =
        clean(req.body.orderAwb) ||
        clean(req.body.order_awb) ||
        clean(req.body.awbNumber) ||
        clean(req.body.awb_number) ||
        clean(req.body.awb) ||
        clean(req.body.orderId) ||
        clean(req.body.order_id);

      // Validation
      if (!category || !message) {
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "Category and message are required.",
        });
      }

      if (category.length > 100) {
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "Category cannot exceed 100 characters.",
        });
      }

      if (orderAwb.length > 100) {
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "Order ID / AWB cannot exceed 100 characters.",
        });
      }

      if (message.length > MAX_MESSAGE_LENGTH) {
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "Message cannot exceed 500 characters.",
        });
      }

      const sellerId = req.sellerId;
      const ticketNumber = generateTicketNumber();

      const attachment = req.file
        ? `uploads/${req.file.filename}`
        : null;

      connection = await pool.getConnection();

      await connection.beginTransaction();
      transactionStarted = true;

      // Insert ticket using actual database columns.
      const [ticketResult] = await connection.query(
        `INSERT INTO support_tickets
        (
          ticket_number,
          seller_id,
          category,
          order_awb,
          message,
          attachment,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'open')`,
        [
          ticketNumber,
          sellerId,
          category,
          orderAwb || null,
          message,
          attachment,
        ]
      );

      const ticketId = ticketResult.insertId;
      // Save seller's original ticket message in conversation
await connection.query(
  `INSERT INTO support_ticket_replies
  (
    ticket_id,
    sender_type,
    sender_id,
    message,
    attachment
  )
  VALUES (?, 'seller', ?, ?, ?)`,
  [
    ticketId,
    sellerId,
    message,
    attachment,
  ]
);

      await connection.commit();
      transactionStarted = false;

      // ==================================================
      // SELLER NOTIFICATION
      // Existing notifications table
      // ==================================================

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
          VALUES (?, ?, ?, ?, ?, ?, 0)`,
          [
            sellerId,
            "Support Ticket Submitted",
            `Your support ticket ${ticketNumber} has been submitted successfully.`,
            "support_ticket",
            "support_ticket",
            ticketId,
          ]
        );
      } catch (notificationError) {
        console.error(
          "TICKET NOTIFICATION ERROR:",
          notificationError
        );
      }

      return res.status(201).json({
        success: true,
        message: "Support ticket submitted successfully.",

        ticket: {
          id: ticketId,
          ticketNumber,
          sellerId,
          category,
          subject: category,
          orderId: orderAwb,
          orderAwb,
          awbNumber: orderAwb,
          message,
          attachment,
          status: "open",
        },
      });

    } catch (error) {
      if (connection && transactionStarted) {
        try {
          await connection.rollback();
        } catch (rollbackError) {
          console.error("TICKET ROLLBACK ERROR:", rollbackError);
        }
      }

      removeUploadedFile(req.file);

      console.error("CREATE SUPPORT TICKET ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to submit support ticket.",
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  }
);

// ======================================================
// GET SELLER TICKETS
// GET /api/tickets/my
// ======================================================

router.get("/my", authenticateSeller, async (req, res) => {
  try {
    const [tickets] = await pool.query(
      `SELECT
        id,
        ticket_number AS ticketNumber,
        category,
        category AS subject,
        order_awb AS orderId,
        order_awb AS orderAwb,
        order_awb AS awbNumber,
        message,
        attachment,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
       FROM support_tickets
       WHERE seller_id = ?
       ORDER BY id DESC`,
      [req.sellerId]
    );

    return res.status(200).json({
      success: true,
      count: tickets.length,
      tickets,
    });

  } catch (error) {
    console.error("FETCH SELLER TICKETS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch your support tickets.",
    });
  }
});

// ======================================================
// GET SELLER TICKET CONVERSATION
// GET /api/tickets/:id
// ======================================================

router.get("/:id", authenticateSeller, async (req, res) => {
  try {
    const ticketId = clean(req.params.id);

    if (!ticketId) {
      return res.status(400).json({
        success: false,
        message: "Ticket ID is required.",
      });
    }

    // Check that this ticket belongs to the logged-in seller.
    const [tickets] = await pool.query(
      `SELECT
        id,
        ticket_number AS ticketNumber,
        seller_id AS sellerId,
        category,
        category AS subject,
        order_awb AS orderId,
        order_awb AS orderAwb,
        message,
        attachment,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
       FROM support_tickets
       WHERE (ticket_number = ? OR id = ?)
         AND seller_id = ?
       LIMIT 1`,
      [ticketId, ticketId, req.sellerId]
    );

    if (!tickets.length) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found.",
      });
    }

    const ticket = tickets[0];

    // Fetch original message and all replies from the same conversation.
    const [replies] = await pool.query(
      `SELECT
        id,
        ticket_id AS ticketId,
        sender_type AS senderType,
        sender_id AS senderId,
        message,
        attachment,
        created_at AS createdAt
       FROM support_ticket_replies
       WHERE ticket_id = ?
       ORDER BY id ASC`,
      [ticket.id]
    );

    return res.status(200).json({
      success: true,
      ticket,
      replies,
    });

  } catch (error) {
    console.error("FETCH TICKET CONVERSATION ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load ticket conversation.",
    });
  }
});
// ======================================================
// SELLER REPLY TO TICKET
// POST /api/tickets/:id/replies
// ======================================================

router.post(
  "/:id/replies",
  authenticateSeller,

  (req, res, next) => {
    upload.single("attachment")(req, res, (error) => {
      if (error) {
        return res.status(400).json({
          success: false,
          message: error.message || "Attachment upload failed.",
        });
      }

      next();
    });
  },

  async (req, res) => {
    let connection;
    let transactionStarted = false;

    try {
      const ticketId = clean(req.params.id);
      const message = clean(req.body.message);

      if (!ticketId || !message) {
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "Ticket ID and reply message are required.",
        });
      }

      if (message.length > MAX_MESSAGE_LENGTH) {
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "Reply cannot exceed 500 characters.",
        });
      }

      connection = await pool.getConnection();
      await connection.beginTransaction();
      transactionStarted = true;

      // Verify ticket ownership and status
      const [tickets] = await connection.query(
        `SELECT id, status
         FROM support_tickets
         WHERE (ticket_number = ? OR id = ?)
           AND seller_id = ?
         LIMIT 1
         FOR UPDATE`,
        [ticketId, ticketId, req.sellerId]
      );

      if (!tickets.length) {
        await connection.rollback();
        transactionStarted = false;
        removeUploadedFile(req.file);

        return res.status(404).json({
          success: false,
          message: "Ticket not found.",
        });
      }

      const ticket = tickets[0];
      const currentStatus = String(ticket.status || "").toLowerCase();

      if (["closed", "resolved"].includes(currentStatus)) {
        await connection.rollback();
        transactionStarted = false;
        removeUploadedFile(req.file);

        return res.status(400).json({
          success: false,
          message: "This ticket is closed. Please reopen it before replying.",
        });
      }

      const attachment = req.file
        ? `uploads/${req.file.filename}`
        : null;

      // Save seller reply in the same conversation table
      const [replyResult] = await connection.query(
        `INSERT INTO support_ticket_replies
         (
           ticket_id,
           sender_type,
           sender_id,
           message,
           attachment
         )
         VALUES (?, 'seller', ?, ?, ?)`,
        [
          ticket.id,
          req.sellerId,
          message,
          attachment,
        ]
      );

      await connection.query(
        `UPDATE support_tickets
         SET updated_at = NOW()
         WHERE id = ?`,
        [ticket.id]
      );

      await connection.commit();
      transactionStarted = false;

      return res.status(201).json({
        success: true,
        message: "Reply sent successfully.",
        reply: {
          id: replyResult.insertId,
          ticketId: ticket.id,
          senderType: "seller",
          senderId: req.sellerId,
          message,
          attachment,
          createdAt: new Date(),
        },
      });

    } catch (error) {
      if (connection && transactionStarted) {
        try {
          await connection.rollback();
        } catch (rollbackError) {
          console.error("REPLY ROLLBACK ERROR:", rollbackError);
        }
      }

      removeUploadedFile(req.file);

      console.error("SELLER TICKET REPLY ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to send ticket reply.",
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  }
);
module.exports = router;
