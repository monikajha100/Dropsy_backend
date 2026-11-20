
const express = require("express");
const router = express.Router();
const pool = require("./pool");
const crypto = require("crypto");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { ensureInvoice } = require("./invoiceService");

const TABLE = "dropshy_seller_products";
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const MAX_IMAGES = 4;

const UPLOAD_DIR = path.resolve(
  __dirname,
  "../../uploads/products"
);

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ======================================================
// IMAGE UPLOAD
// ======================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },

  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const name =
      Date.now() +
      "-" +
      crypto.randomBytes(6).toString("hex") +
      ext;

    cb(null, name);
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: MAX_IMAGES,
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/webp",
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG and WEBP images are allowed"));
    }

    cb(null, true);
  },
});

function uploadProductImages(req, res, next) {
  upload.array("product_image", MAX_IMAGES)(req, res, (error) => {
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.message || "Image upload failed",
      });
    }

    next();
  });
}

// ======================================================
// SELLER AUTHENTICATION
// ======================================================

async function authenticateSeller(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7).trim()
      : "";

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Seller login required",
      });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const [sessions] = await pool.query(
      `SELECT s.id AS seller_id
       FROM seller_login_sessions ls
       INNER JOIN sellers s ON s.id = ls.seller_id
       WHERE ls.session_token = ?
       AND ls.status = 'active'
       AND ls.expires_at > NOW()
       LIMIT 1`,
      [hashedToken]
    );

    if (!sessions.length) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired seller session",
      });
    }

    req.sellerId = sessions[0].seller_id;
    next();

  } catch (error) {
    console.error("Seller authentication error:", error);

    return res.status(500).json({
      success: false,
      message: "Seller authentication failed",
    });
  }
}

// ======================================================
// HELPERS
// ======================================================

function makeSKU() {
  return (
    "DS-" +
    Date.now() +
    "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase()
  );
}

function validId(id) {
  return /^[1-9]\d*$/.test(String(id || ""));
}

function numberValue(value, fallback = 0) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  const n = Number(value);
  return Number.isFinite(n) ? n : NaN;
}

function optionalNumber(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function parseArray(value) {
  if (Array.isArray(value)) return value;

  if (!value) return [];

  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function imageUrl(file) {
  return "/uploads/products/" + file.filename;
}

function deleteUploadedFiles(files = []) {
  for (const file of files) {
    if (file && file.path && fs.existsSync(file.path)) {
      try {
        fs.unlinkSync(file.path);
      } catch (error) {
        console.error("Image cleanup error:", error.message);
      }
    }
  }
}

function getProductData(body) {
  const product_name = String(body.product_name || "").trim();

  const category_name = String(
    body.category_name || body.category || ""
  ).trim();

  const category_id = optionalNumber(body.category_id);
  const subcategory_id = optionalNumber(body.subcategory_id);

  const subcategory_name = String(
    body.subcategory_name || ""
  ).trim();

  const selling_price = numberValue(body.selling_price, NaN);
  const wholesale_price = numberValue(body.wholesale_price, 0);
  const mrp = numberValue(body.mrp, selling_price);
  const stock_quantity = numberValue(body.stock_quantity, 0);

  const description = String(body.description || "").trim();

  const colors = parseArray(body.colors);
  const sizes = parseArray(body.sizes);
  const sections = parseArray(body.sections);

  const sku = String(body.sku || "").trim();

  return {
    product_name,
    category_id,
    category_name,
    subcategory_id,
    subcategory_name,
    selling_price,
    wholesale_price,
    mrp,
    stock_quantity,
    description,
    colors,
    sizes,
    sections,
    sku,
  };
}

function validateProduct(data) {
  if (!data.product_name || !data.category_name) {
    return "Product name and category are required";
  }

  if (data.product_name.length > 255) {
    return "Product name cannot exceed 255 characters";
  }

  if (
    !Number.isFinite(data.selling_price) ||
    data.selling_price <= 0
  ) {
    return "Enter a valid selling price";
  }

  if (
    !Number.isFinite(data.wholesale_price) ||
    data.wholesale_price < 0 ||
    data.wholesale_price > data.selling_price
  ) {
    return "Enter a valid wholesale price";
  }

  if (
    !Number.isFinite(data.mrp) ||
    data.mrp < data.selling_price
  ) {
    return "MRP must be at least selling price";
  }

  if (
    !Number.isInteger(data.stock_quantity) ||
    data.stock_quantity < 0
  ) {
    return "Stock must be a non-negative whole number";
  }

  if (data.category_id !== null &&
      (!Number.isInteger(data.category_id) || data.category_id <= 0)) {
    return "Invalid category ID";
  }

  if (data.subcategory_id !== null &&
      (!Number.isInteger(data.subcategory_id) || data.subcategory_id <= 0)) {
    return "Invalid subcategory ID";
  }

  if (data.sku.length > 100) {
    return "SKU cannot exceed 100 characters";
  }

  return null;
}

function getExistingImages(value) {
  return parseArray(value).filter(
    (item) =>
      typeof item === "string" &&
      item.startsWith("/uploads/products/")
  );
}

// ======================================================
// 1. ADD PRODUCT
// POST /api/seller-products
// ======================================================

router.post(
  "/",
  authenticateSeller,
  uploadProductImages,
  async (req, res) => {
    try {
      const data = getProductData(req.body || {});
      const errorMessage = validateProduct(data);

      if (errorMessage) {
        deleteUploadedFiles(req.files);
        return res.status(400).json({
          success: false,
          message: errorMessage,
        });
      }

      const images = (req.files || []).map(imageUrl);

      if (!images.length) {
        return res.status(400).json({
          success: false,
          message: "Please upload at least one product image",
        });
      }

      const finalSKU = data.sku || makeSKU();

      const [existingSKU] = await pool.query(
        `SELECT id
         FROM ${TABLE}
         WHERE sku = ?
         LIMIT 1`,
        [finalSKU]
      );

      if (existingSKU.length) {
        deleteUploadedFiles(req.files);

        return res.status(409).json({
          success: false,
          message: "This SKU already exists",
        });
      }

      const [result] = await pool.query(
        `INSERT INTO ${TABLE}
        (
          seller_id,
          product_name,
          sku,
          description,
          category_id,
          category_name,
          subcategory_id,
          subcategory_name,
          selling_price,
          wholesale_price,
          mrp,
          stock_quantity,
          colors,
          sizes,
          sections,
          product_image,
          product_images,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
        [
          req.sellerId,
          data.product_name,
          finalSKU,
          data.description || null,
          data.category_id,
          data.category_name,
          data.subcategory_id,
          data.subcategory_name || null,
          data.selling_price,
          data.wholesale_price,
          data.mrp,
          data.stock_quantity,
          JSON.stringify(data.colors),
          JSON.stringify(data.sizes),
          JSON.stringify(data.sections),
          images[0],
          JSON.stringify(images),
        ]
      );

      const [products] = await pool.query(
        `SELECT *
         FROM ${TABLE}
         WHERE id = ? AND seller_id = ?
         LIMIT 1`,
        [result.insertId, req.sellerId]
      );

      return res.status(201).json({
        success: true,
        message: "Product submitted for admin approval",
        product: products[0],
      });

    } catch (error) {
      deleteUploadedFiles(req.files);

      console.error("Add seller product error:", error);

      return res.status(500).json({
        success: false,
        message: "Could not add product",
      });
    }
  }
);

// ======================================================
// 2. GET MY PRODUCTS
// GET /api/seller-products/my
// ======================================================

router.get("/my", authenticateSeller, async (req, res) => {
  try {
    const [products] = await pool.query(
      `SELECT *
       FROM ${TABLE}
       WHERE seller_id = ?
       ORDER BY id DESC`,
      [req.sellerId]
    );

    return res.json({
      success: true,
      count: products.length,
      products,
    });

  } catch (error) {
    console.error("Get seller products error:", error);

    return res.status(500).json({
      success: false,
      message: "Could not fetch seller products",
    });
  }
});

// ======================================================
// 3. PRODUCT SUMMARY
// GET /api/seller-products/summary
// ======================================================

router.get("/summary", authenticateSeller, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
        COUNT(*) AS total_products,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_products,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_products,
        SUM(CASE WHEN status = 'inactive' THEN 1 ELSE 0 END) AS inactive_products,
        SUM(CASE WHEN stock_quantity = 0 THEN 1 ELSE 0 END) AS out_of_stock,
        SUM(CASE WHEN stock_quantity > 0 AND stock_quantity <= 20 THEN 1 ELSE 0 END) AS low_stock
       FROM ${TABLE}
       WHERE seller_id = ?`,
      [req.sellerId]
    );

    return res.json({
      success: true,
      summary: rows[0],
    });

  } catch (error) {
    console.error("Product summary error:", error);

    return res.status(500).json({
      success: false,
      message: "Could not fetch product summary",
    });
  }
});

// ======================================================
// 4. GET ONE PRODUCT
// GET /api/seller-products/:id
// ======================================================

router.get("/:id", authenticateSeller, async (req, res) => {
  try {
    if (!validId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID",
      });
    }

    const [products] = await pool.query(
      `SELECT *
       FROM ${TABLE}
       WHERE id = ? AND seller_id = ?
       LIMIT 1`,
      [req.params.id, req.sellerId]
    );

    if (!products.length) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    return res.json({
      success: true,
      product: products[0],
    });

  } catch (error) {
    console.error("Get single product error:", error);

    return res.status(500).json({
      success: false,
      message: "Could not fetch product",
    });
  }
});

// ======================================================
// 5. UPDATE PRODUCT
// PUT /api/seller-products/:id
// ======================================================

router.put(
  "/:id",
  authenticateSeller,
  uploadProductImages,
  async (req, res) => {
    try {
      if (!validId(req.params.id)) {
        deleteUploadedFiles(req.files);

        return res.status(400).json({
          success: false,
          message: "Invalid product ID",
        });
      }

      const [owned] = await pool.query(
        `SELECT *
         FROM ${TABLE}
         WHERE id = ? AND seller_id = ?
         LIMIT 1`,
        [req.params.id, req.sellerId]
      );

      if (!owned.length) {
        deleteUploadedFiles(req.files);

        return res.status(404).json({
          success: false,
          message: "Product not found",
        });
      }

      const data = getProductData(req.body || {});
      const errorMessage = validateProduct(data);

      if (errorMessage) {
        deleteUploadedFiles(req.files);

        return res.status(400).json({
          success: false,
          message: errorMessage,
        });
      }

      const existingImages = req.body.existing_images !== undefined
        ? getExistingImages(req.body.existing_images)
        : getExistingImages(owned[0].product_images);

      const newImages = (req.files || []).map(imageUrl);
      const allImages = [...existingImages, ...newImages];

      if (!allImages.length) {
        deleteUploadedFiles(req.files);

        return res.status(400).json({
          success: false,
          message: "At least one product image is required",
        });
      }

      if (allImages.length > MAX_IMAGES) {
        deleteUploadedFiles(req.files);

        return res.status(400).json({
          success: false,
          message: "Maximum 4 product images are allowed",
        });
      }

      const finalSKU = data.sku || owned[0].sku;

      const [duplicate] = await pool.query(
        `SELECT id
         FROM ${TABLE}
         WHERE sku = ? AND id != ?
         LIMIT 1`,
        [finalSKU, req.params.id]
      );

      if (duplicate.length) {
        deleteUploadedFiles(req.files);

        return res.status(409).json({
          success: false,
          message: "This SKU is already in use",
        });
      }

      await pool.query(
        `UPDATE ${TABLE}
         SET product_name = ?,
             sku = ?,
             description = ?,
             category_id = ?,
             category_name = ?,
             subcategory_id = ?,
             subcategory_name = ?,
             selling_price = ?,
             wholesale_price = ?,
             mrp = ?,
             stock_quantity = ?,
             colors = ?,
             sizes = ?,
             sections = ?,
             product_image = ?,
             product_images = ?,
             updated_at = NOW()
         WHERE id = ? AND seller_id = ?`,
        [
          data.product_name,
          finalSKU,
          data.description || null,
          data.category_id,
          data.category_name,
          data.subcategory_id,
          data.subcategory_name || null,
          data.selling_price,
          data.wholesale_price,
          data.mrp,
          data.stock_quantity,
          JSON.stringify(data.colors),
          JSON.stringify(data.sizes),
          JSON.stringify(data.sections),
          allImages[0],
          JSON.stringify(allImages),
          req.params.id,
          req.sellerId,
        ]
      );

      return res.json({
        success: true,
        message: "Product updated successfully",
      });

    } catch (error) {
      deleteUploadedFiles(req.files);

      console.error("Update seller product error:", error);

      return res.status(500).json({
        success: false,
        message: "Could not update product",
      });
    }
  }
);

// ======================================================
// 6. UPDATE STOCK
// PATCH /api/seller-products/:id/stock
// ======================================================

router.patch("/:id/stock", authenticateSeller, async (req, res) => {
  try {
    if (!validId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID",
      });
    }

    const stock = Number(req.body.stock_quantity);

    if (!Number.isInteger(stock) || stock < 0) {
      return res.status(400).json({
        success: false,
        message: "Enter valid stock quantity",
      });
    }

    const [result] = await pool.query(
      `UPDATE ${TABLE}
       SET stock_quantity = ?,
           status = CASE
             WHEN ? = 0 THEN 'out_of_stock'
             WHEN status = 'out_of_stock' THEN 'pending'
             ELSE status
           END,
           updated_at = NOW()
       WHERE id = ? AND seller_id = ?`,
      [stock, stock, req.params.id, req.sellerId]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    return res.json({
      success: true,
      message: "Stock updated successfully",
      stock_quantity: stock,
    });

  } catch (error) {
    console.error("Update stock error:", error);

    return res.status(500).json({
      success: false,
      message: "Could not update stock",
    });
  }
});

// ======================================================
// 7. DELETE PRODUCT
// DELETE /api/seller-products/:id
// ======================================================

router.delete("/:id", authenticateSeller, async (req, res) => {
  try {
    if (!validId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID",
      });
    }

    const [result] = await pool.query(
      `DELETE FROM ${TABLE}
       WHERE id = ? AND seller_id = ?`,
      [req.params.id, req.sellerId]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    return res.json({
      success: true,
      message: "Product deleted successfully",
    });

  } catch (error) {
    console.error("Delete seller product error:", error);

    return res.status(500).json({
      success: false,
      message: "Could not delete product",
    });
  }
});
// ======================================================
// INVOICE PDF
// GET /api/seller-products/:id/invoice
// ======================================================

router.get("/:id/invoice", authenticateSeller, async (req, res) => {
  try {
    if (!validId(req.params.id)) {
      return res.status(400).json({ success: false, message: "Invalid product ID" });
    }

    const [rows] = await pool.query(
      `SELECT * FROM ${TABLE} WHERE id = ? AND seller_id = ? LIMIT 1`,
      [req.params.id, req.sellerId]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }

    const p = rows[0];

    if (String(p.status).toLowerCase() !== "active") {
      return res.status(403).json({
        success: false,
        message: "Invoice product approve hone ke baad available hoga",
      });
    }

    const PDFDocument = require("pdfkit");
    const doc = new PDFDocument({ size: "A4", margin: 50 });

    const invoiceNo = `INV-${p.id}-${Date.now().toString().slice(-6)}`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${invoiceNo}.pdf"`);
    doc.pipe(res);

    const rs = (v) => "Rs. " + Number(v || 0).toLocaleString("en-IN");

    doc.fontSize(22).text("DROPSHY", { align: "left" });
    doc.fontSize(10).fillColor("#667085").text("Product Invoice");
    doc.moveDown();

    doc.fillColor("#000").fontSize(11);
    doc.text(`Invoice No: ${invoiceNo}`);
    doc.text(`Date: ${new Date().toLocaleDateString("en-IN")}`);
    doc.text(`Seller ID: ${p.seller_id}`);
    doc.moveDown();

    doc.fontSize(13).text("Product Details", { underline: true });
    doc.moveDown(0.5).fontSize(11);
    doc.text(`Name: ${p.product_name}`);
    doc.text(`SKU: ${p.sku}`);
    doc.text(`Category: ${p.category_name}${p.subcategory_name ? " / " + p.subcategory_name : ""}`);
    doc.text(`Stock: ${p.stock_quantity}`);
    doc.moveDown();

    doc.fontSize(13).text("Pricing", { underline: true });
    doc.moveDown(0.5).fontSize(11);
    doc.text(`MRP: ${rs(p.mrp)}`);
    doc.text(`Wholesale Price: ${rs(p.wholesale_price)}`);
    doc.text(`Selling Price: ${rs(p.selling_price)}`);

    doc.end();
  } catch (error) {
    console.error("Invoice error:", error);
    if (!res.headersSent) {
      return res.status(500).json({ success: false, message: "Invoice generation failed" });
    }
  }
});

module.exports = router;
