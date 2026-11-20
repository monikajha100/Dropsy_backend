
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const { ensureInvoice } = require("./invoiceService");
const app = express();

// ======================================================
// CORS CONFIGURATION
// ======================================================

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
  "https://dropshy.in",
  "https://www.dropshy.in",
  "https://product.dropshy.in",
];

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    console.error("[CORS BLOCKED]", origin);
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

// ======================================================
// BODY PARSER
// ======================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ======================================================
// REQUEST LOGGER
// ======================================================

app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.originalUrl}`);
  next();
});

// ======================================================
// STATIC UPLOADS
// ======================================================

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ======================================================
// ROUTES
// ======================================================

// Banner
app.use("/api/banners", require("./src/routes/banner"));

// Blog
app.use("/api", require("./src/routes/blog"));

// Users
// Users
const usersRouter = require("./src/routes/users");

console.log(
  "[USERS ROUTES LOADED]",
  usersRouter.stack
    .filter((layer) => layer.route)
    .map((layer) => ({
      path: layer.route.path,
      methods: Object.keys(layer.route.methods),
    }))
);

app.use("/api", usersRouter);

// Admin
app.use("/admin", require("./src/routes/admin"));
//app.use("SellerApi", require("./src/routes/SellerApi"));

// Seller
app.use("/api/sellers", require("./src/routes/sellors"));

// KYC
app.use("/api/kyc", require("./src/routes/kyc"));

// Dashboard
app.use("/api/dashboard", require("./src/routes/dashboard"));

// Orders
app.use("/api/order", require("./src/routes/order"));

// Wallet
app.use("/api/wallet", require("./src/routes/wallet"));

// Payment
app.use("/api/payment", require("./src/routes/payment"));

// Product
app.use("/api/product", require("./src/routes/product"));

// GST Ledger
app.use("/api/gst-ledger", require("./src/routes/gstLedger"));

// Categories
app.use("/api/categories", require("./src/routes/categories"));
app.use("/api/invoiceServices", require("./src/routes/invoiceService"));
// Support Tickets
app.use("/api/tickets", require("./src/routes/tickets"));
app.use("/api/seller-warehouses",require("./src/routes/sellerWarehouses"));
// Seller Products
app.use("/api/seller-products", require("./src/routes/sellerproduct"));
// Vendors
app.use("/api/vendors", require("./src/routes/vendors"));

// ======================================================
// HEALTH CHECK
// ======================================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Dropshy Backend is running",
    port: process.env.PORT || 5000,
  });
});

// ======================================================
// ERROR HANDLER
// ======================================================

app.use((err, req, res, next) => {
  console.error("[SERVER ERROR]", err.stack || err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: "Internal server error",
    error:
      process.env.NODE_ENV === "development"
        ? err.message
        : undefined,
  });
});

// ======================================================
// 404 HANDLER
// ======================================================

app.use((req, res) => {
  console.error(`[404] ${req.method} ${req.originalUrl}`);

  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// ======================================================
// START SERVER
// ======================================================

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("--------------------------------------");
  console.log("DROPSHY BACKEND STARTED SUCCESSFULLY");
  console.log(`PORT: ${PORT}`);
  console.log("SELLER API: /api/sellers");
  console.log("KYC API: /api/kyc");
  console.log("WALLET API: /api/wallet");
  console.log("PAYMENT API: /api/payment");
  console.log("GST LEDGER API: /api/gst-ledger");
  console.log("SELLER PRODUCTS API: /api/seller-products");
  console.log("--------------------------------------");
});
