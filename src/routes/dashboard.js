
const express = require("express");
const router = express.Router();
const pool = require("./pool");

// GET /api/dashboard/overview?sellerId=1
router.get("/overview", async (req, res) => {
  try {
    const sellerId = Number(req.query.sellerId);

    if (!Number.isInteger(sellerId) || sellerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid sellerId is required."
      });
    }

    // 1. Seller profile
    const [sellers] = await pool.query(
      `SELECT id, fullName, email, payment_status
       FROM sellers
       WHERE id = ?
       LIMIT 1`,
      [sellerId]
    );

    if (sellers.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Seller not found."
      });
    }

    // 2. Dashboard statistics and wallet balance
    const [statsRows] = await pool.query(
      `SELECT
        (SELECT COUNT(*)
         FROM orders
         WHERE seller_id = ? AND is_archived = 0) AS totalOrders,

        (SELECT COUNT(*)
         FROM orders
         WHERE seller_id = ? AND is_archived = 0
           AND status = 'new') AS newOrders,

        (SELECT COUNT(*)
         FROM orders
         WHERE seller_id = ? AND is_archived = 0
           AND status = 'delivered') AS deliveredOrders,

        (SELECT COUNT(*)
         FROM orders
         WHERE seller_id = ? AND is_archived = 0
           AND status = 'cancelled') AS cancelledOrders,

        (SELECT COUNT(*)
         FROM shipments
         WHERE seller_id = ?) AS totalShipments,

        (SELECT COUNT(*)
         FROM shipments
         WHERE seller_id = ?
           AND shipment_status = 'delivered') AS deliveredShipments,

        (SELECT COUNT(*)
         FROM shipments
         WHERE seller_id = ?
           AND shipment_status IN
           ('picked_up', 'in_transit', 'out_for_delivery',
            'rto_in_transit')) AS inTransitShipments,

        (SELECT COUNT(*)
         FROM shipments
         WHERE seller_id = ?
           AND shipment_status = 'ndr') AS ndrShipments,

        COALESCE(sw.balance, 0.00) AS walletBalance,
        COALESCE(sw.currency, 'INR') AS currency,
        COALESCE(sw.status, 'active') AS walletStatus

       FROM sellers s
       LEFT JOIN seller_wallet sw ON sw.seller_id = s.id
       WHERE s.id = ?`,
      [
        sellerId, sellerId, sellerId, sellerId,
        sellerId, sellerId, sellerId, sellerId,
        sellerId
      ]
    );

    // 3. Recent orders
    const [recentOrders] = await pool.query(
      `SELECT
         id, order_no, order_date, status, order_type,
         zone, payment_mode, invoice_amount,
         customer_name, customer_city
       FROM orders
       WHERE seller_id = ? AND is_archived = 0
       ORDER BY order_date DESC
       LIMIT 5`,
      [sellerId]
    );

    // 4. Recent shipments
    const [recentShipments] = await pool.query(
      `SELECT
         id, order_id, awb_no, tracking_no,
         shipment_status, total_charge,
         estimated_delivery_date, created_at
       FROM shipments
       WHERE seller_id = ?
       ORDER BY created_at DESC
       LIMIT 5`,
      [sellerId]
    );

    return res.status(200).json({
      success: true,
      message: "Dashboard data fetched successfully.",
      data: {
        seller: sellers[0],
        stats: statsRows[0],
        recentOrders,
        recentShipments
      }
    });
  } catch (error) {
    console.error("DASHBOARD OVERVIEW ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch dashboard data.",
      error: error.message
    });
  }
});

module.exports = router;