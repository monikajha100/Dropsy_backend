
const express = require("express");
const crypto = require("crypto");
const pool = require("./pool");

const router = express.Router();

// =====================================================
// SELLER SESSION AUTHENTICATION
// =====================================================

async function authenticateSeller(req, res, next) {
    try {
        const authHeader = req.headers.authorization || "";
        const match = authHeader.match(/^Bearer\s+([a-f0-9]{64})$/i);

        if (!match) {
            return res.status(401).json({
                success: false,
                message: "Please login first."
            });
        }

        const token = match[1];

        const tokenHash = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

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
                message: "Seller session expired. Please login again."
            });
        }

        req.sellerId = Number(sessions[0].seller_id);
        req.sessionId = sessions[0].id;
        req.sessionTokenHash = tokenHash;

        next();

    } catch (error) {
        console.error("Call Support Authentication:", error);

        return res.status(500).json({
            success: false,
            message: "Authentication failed."
        });
    }
}

router.use(authenticateSeller);

// =====================================================
// HELPERS
// =====================================================

function validDate(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))) {
        return false;
    }

    const date = new Date(`${value}T00:00:00`);

    return !Number.isNaN(date.getTime()) &&
        date.toISOString().slice(0, 10) === value;
}

function isWorkingDay(dateString, workingDays) {
    const date = new Date(`${dateString}T12:00:00`);
    const day = date.getDay();

    const days = String(workingDays || "Monday-Saturday")
        .toLowerCase();

    if (days.includes("monday-saturday")) {
        return day >= 1 && day <= 6;
    }

    if (days.includes("monday-friday")) {
        return day >= 1 && day <= 5;
    }

    return day >= 1 && day <= 6;
}

function timeToMinutes(time) {
    const parts = String(time).slice(0, 8).split(":");

    return Number(parts[0]) * 60 + Number(parts[1]);
}

function minutesToTime(minutes) {
    const hours = String(Math.floor(minutes / 60)).padStart(2, "0");
    const mins = String(minutes % 60).padStart(2, "0");

    return `${hours}:${mins}:00`;
}

function localToday() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const day = String(now.getDate()).padStart(2, "0");

    return `${year}-${month}-${day}`;
}

async function getActiveManager(connection = pool) {
    const [rows] = await connection.query(
        `SELECT id, name, phone, email, working_days,
                start_time, end_time
         FROM support_managers
         WHERE is_active = 1
         ORDER BY id ASC
         LIMIT 1`
    );

    return rows[0] || null;
}

async function generateSlots(date, manager) {
    const [existing] = await pool.query(
        `SELECT id
         FROM support_slots
         WHERE manager_id = ? AND slot_date = ?
         LIMIT 1`,
        [manager.id, date]
    );

    if (existing.length) return;

    if (!isWorkingDay(date, manager.working_days)) return;

    const start = timeToMinutes(manager.start_time);
    const end = timeToMinutes(manager.end_time);
    const duration = 30;

    if (end <= start) return;

    const values = [];

    for (
        let minute = start;
        minute + duration <= end;
        minute += duration
    ) {
        values.push([
            manager.id,
            date,
            minutesToTime(minute),
            minutesToTime(minute + duration)
        ]);
    }

    if (values.length) {
        await pool.query(
            `INSERT IGNORE INTO support_slots
             (manager_id, slot_date, start_time, end_time)
             VALUES ?`,
            [values]
        );
    }
}

async function verifySeller(sellerId) {
    const [rows] = await pool.query(
        "SELECT id FROM sellers WHERE id = ? LIMIT 1",
        [sellerId]
    );

    return rows.length > 0;
}

// =====================================================
// GET MANAGER DETAILS
// GET /api/call-support/manager
// =====================================================

router.get("/manager", async (req, res) => {
    try {
        const manager = await getActiveManager();

        if (!manager) {
            return res.status(404).json({
                success: false,
                message: "Support manager is not configured."
            });
        }

        return res.json({
            success: true,
            manager
        });

    } catch (error) {
        console.error("Manager API:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to load support manager."
        });
    }
});

// =====================================================
// GET AVAILABLE SLOTS
// GET /api/call-support/slots?date=2026-11-28
// =====================================================

router.get("/slots", async (req, res) => {
    try {
        const date = req.query.date;

        if (!validDate(date) || date < localToday()) {
            return res.status(400).json({
                success: false,
                message: "Please select a valid current or future date."
            });
        }

        const manager = await getActiveManager();

        if (!manager) {
            return res.status(404).json({
                success: false,
                message: "Support manager is not configured."
            });
        }

        if (!isWorkingDay(date, manager.working_days)) {
            return res.json({
                success: true,
                slots: [],
                message: "Support is not available on this day."
            });
        }

        await generateSlots(date, manager);

        const [slots] = await pool.query(
            `SELECT
                id,
                slot_date,
                start_time,
                end_time,
                is_available
             FROM support_slots
             WHERE manager_id = ?
               AND slot_date = ?
             ORDER BY start_time ASC`,
            [manager.id, date]
        );

        const now = new Date();
        const today = localToday();
        const currentMinutes = now.getHours() * 60 + now.getMinutes();

        const result = slots.map(slot => {
            const past = date === today &&
                timeToMinutes(slot.start_time) <= currentMinutes;

            return {
                ...slot,
                is_available: Boolean(slot.is_available) && !past
            };
        });

        return res.json({
            success: true,
            date,
            manager_id: manager.id,
            slots: result
        });

    } catch (error) {
        console.error("Slots API:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to load available slots."
        });
    }
});

// =====================================================
// CREATE BOOKING
// POST /api/call-support/bookings
// =====================================================

router.post("/bookings", async (req, res) => {
    let connection;

    try {
        const sellerId = req.sellerId;
        const { slot_id, support_type } = req.body;

        if (!slot_id || !support_type || !String(support_type).trim()) {
            return res.status(400).json({
                success: false,
                message: "Slot and support type are required."
            });
        }

        if (!(await verifySeller(sellerId))) {
            return res.status(403).json({
                success: false,
                message: "Seller account was not found."
            });
        }

        connection = await pool.getConnection();

        await connection.beginTransaction();

        const [slotRows] = await connection.query(
            `SELECT *
             FROM support_slots
             WHERE id = ?
             FOR UPDATE`,
            [slot_id]
        );

        const slot = slotRows[0];

        if (!slot || !slot.is_available) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "This slot is no longer available. Please select another slot."
            });
        }

        const manager = await getActiveManager(connection);

        if (!manager || Number(manager.id) !== Number(slot.manager_id)) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "This support slot is no longer valid."
            });
        }

        const [existing] = await connection.query(
            `SELECT id
             FROM support_bookings
             WHERE slot_id = ?
               AND status IN ('Confirmed', 'Completed')
             LIMIT 1`,
            [slot.id]
        );

        if (existing.length) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "This slot has already been booked."
            });
        }

        const [updateResult] = await connection.query(
            `UPDATE support_slots
             SET is_available = 0
             WHERE id = ? AND is_available = 1`,
            [slot.id]
        );

        if (updateResult.affectedRows !== 1) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "This slot has just been booked by someone else."
            });
        }

        const reference =
            "CS" + Date.now() + Math.floor(1000 + Math.random() * 9000);

        const [bookingResult] = await connection.query(
            `INSERT INTO support_bookings
             (booking_reference, seller_id, manager_id, slot_id,
              booking_date, start_time, end_time, support_type, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Confirmed')`,
            [
                reference,
                sellerId,
                manager.id,
                slot.id,
                slot.slot_date,
                slot.start_time,
                slot.end_time,
                String(support_type).trim()
            ]
        );

        await connection.commit();

        return res.status(201).json({
            success: true,
            message: "Your support call has been confirmed.",
            booking: {
                id: bookingResult.insertId,
                booking_reference: reference,
                booking_date: slot.slot_date,
                start_time: slot.start_time,
                end_time: slot.end_time,
                support_type: String(support_type).trim(),
                status: "Confirmed",
                manager
            }
        });

    } catch (error) {
        if (connection) {
            await connection.rollback();
        }

        console.error("Create booking API:", error);

        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                success: false,
                message: "This slot is already booked."
            });
        }

        return res.status(500).json({
            success: false,
            message: "Unable to create booking."
        });

    } finally {
        if (connection) connection.release();
    }
});

// =====================================================
// GET SELLER BOOKINGS
// GET /api/call-support/bookings
// =====================================================

router.get("/bookings", async (req, res) => {
    try {
        const [bookings] = await pool.query(
            `SELECT
                b.id,
                b.booking_reference,
                b.booking_date,
                b.start_time,
                b.end_time,
                b.support_type,
                b.status,
                b.created_at,
                m.name AS manager_name,
                m.phone AS manager_phone
             FROM support_bookings b
             LEFT JOIN support_managers m ON m.id = b.manager_id
             WHERE b.seller_id = ?
             ORDER BY b.booking_date DESC, b.start_time DESC`,
            [req.sellerId]
        );

        return res.json({
            success: true,
            bookings
        });

    } catch (error) {
        console.error("Bookings API:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to load bookings."
        });
    }
});

// =====================================================
// RESCHEDULE BOOKING
// PATCH /api/call-support/bookings/:id/reschedule
// Body: { "slot_id": 123 }
// =====================================================

router.patch("/bookings/:id/reschedule", async (req, res) => {
    let connection;

    try {
        const bookingId = Number(req.params.id);
        const newSlotId = Number(req.body.slot_id);

        if (
            !Number.isInteger(bookingId) || bookingId <= 0 ||
            !Number.isInteger(newSlotId) || newSlotId <= 0
        ) {
            return res.status(400).json({
                success: false,
                message: "Valid booking ID and new slot ID are required."
            });
        }

        connection = await pool.getConnection();

        await connection.beginTransaction();

        const [bookingRows] = await connection.query(
            `SELECT *
             FROM support_bookings
             WHERE id = ? AND seller_id = ?
             FOR UPDATE`,
            [bookingId, req.sellerId]
        );

        const booking = bookingRows[0];

        if (!booking) {
            await connection.rollback();

            return res.status(404).json({
                success: false,
                message: "Booking not found."
            });
        }

        if (booking.status !== "Confirmed") {
            await connection.rollback();

            return res.status(400).json({
                success: false,
                message: "Only confirmed bookings can be rescheduled."
            });
        }

        if (Number(booking.slot_id) === newSlotId) {
            await connection.rollback();

            return res.status(400).json({
                success: false,
                message: "Please select a different slot."
            });
        }

        const [slotRows] = await connection.query(
            `SELECT *
             FROM support_slots
             WHERE id = ?
             FOR UPDATE`,
            [newSlotId]
        );

        const newSlot = slotRows[0];

        if (!newSlot || !newSlot.is_available) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "The selected slot is not available."
            });
        }

        if (Number(newSlot.manager_id) !== Number(booking.manager_id)) {
            await connection.rollback();

            return res.status(400).json({
                success: false,
                message: "Selected slot does not belong to your support manager."
            });
        }

        const [updatedSlot] = await connection.query(
            `UPDATE support_slots
             SET is_available = 0
             WHERE id = ? AND is_available = 1`,
            [newSlotId]
        );

        if (updatedSlot.affectedRows !== 1) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "This slot has just been booked by someone else."
            });
        }

        await connection.query(
            `UPDATE support_slots
             SET is_available = 1
             WHERE id = ?`,
            [booking.slot_id]
        );

        await connection.query(
            `UPDATE support_bookings
             SET slot_id = ?,
                 booking_date = ?,
                 start_time = ?,
                 end_time = ?,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ? AND seller_id = ?`,
            [
                newSlot.id,
                newSlot.slot_date,
                newSlot.start_time,
                newSlot.end_time,
                bookingId,
                req.sellerId
            ]
        );

        await connection.commit();

        return res.json({
            success: true,
            message: "Your support call has been rescheduled.",
            booking: {
                id: bookingId,
                booking_date: newSlot.slot_date,
                start_time: newSlot.start_time,
                end_time: newSlot.end_time,
                status: "Confirmed"
            }
        });

    } catch (error) {
        if (connection) {
            await connection.rollback();
        }

        console.error("Reschedule API:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to reschedule booking."
        });

    } finally {
        if (connection) connection.release();
    }
});

// =====================================================
// CANCEL BOOKING
// PATCH /api/call-support/bookings/:id/cancel
// =====================================================

router.patch("/bookings/:id/cancel", async (req, res) => {
    let connection;

    try {
        const bookingId = Number(req.params.id);

        if (!Number.isInteger(bookingId) || bookingId <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid booking ID."
            });
        }

        connection = await pool.getConnection();

        await connection.beginTransaction();

        const [rows] = await connection.query(
            `SELECT *
             FROM support_bookings
             WHERE id = ? AND seller_id = ?
             FOR UPDATE`,
            [bookingId, req.sellerId]
        );

        const booking = rows[0];

        if (!booking) {
            await connection.rollback();

            return res.status(404).json({
                success: false,
                message: "Booking not found."
            });
        }

        if (booking.status !== "Confirmed") {
            await connection.rollback();

            return res.status(400).json({
                success: false,
                message: "Only confirmed bookings can be cancelled."
            });
        }

        await connection.query(
            `UPDATE support_bookings
             SET status = 'Cancelled',
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ? AND seller_id = ?`,
            [bookingId, req.sellerId]
        );

        await connection.query(
            `UPDATE support_slots
             SET is_available = 1
             WHERE id = ?`,
            [booking.slot_id]
        );

        await connection.commit();

        return res.json({
            success: true,
            message: "Your support call has been cancelled."
        });

    } catch (error) {
        if (connection) {
            await connection.rollback();
        }

        console.error("Cancel booking API:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to cancel booking."
        });

    } finally {
        if (connection) connection.release();
    }
});

// =====================================================
// DASHBOARD STATS
// GET /api/call-support/stats
// =====================================================

router.get("/stats", async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT
                COUNT(*) AS total_bookings,
                SUM(status = 'Confirmed') AS confirmed,
                SUM(status = 'Completed') AS completed,
                SUM(status = 'Cancelled') AS cancelled,
                SUM(status = 'Confirmed' AND booking_date >= CURDATE()) AS upcoming
             FROM support_bookings
             WHERE seller_id = ?`,
            [req.sellerId]
        );

        return res.json({
            success: true,
            stats: {
                total: Number(rows[0].total_bookings || 0),
                confirmed: Number(rows[0].confirmed || 0),
                completed: Number(rows[0].completed || 0),
                cancelled: Number(rows[0].cancelled || 0),
                upcoming: Number(rows[0].upcoming || 0)
            }
        });

    } catch (error) {
        console.error("Stats API:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to load booking statistics."
        });
    }
});

module.exports = router;
