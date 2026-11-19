
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const pool = require("./pool");

const router = express.Router();

// ======================================================
// IMAGE UPLOAD DIRECTORY
// ======================================================

const uploadDir = path.join(
  __dirname,
  "..",
  "..",
  "uploads",
  "products"
);

fs.mkdirSync(uploadDir, { recursive: true });

// ======================================================
// MULTER - MULTIPLE IMAGES (MAX 4)
// ======================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },

  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();

    cb(
      null,
      `product-${Date.now()}-${Math.round(Math.random() * 1000000)}${ext}`
    );
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 4,
  },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed."));
    }

    cb(null, true);
  },
});

// ======================================================
// COMMON HELPERS
// ======================================================

function parseJSON(value, fallback = []) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  if (typeof value !== "string") {
    return value;
  }

  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function parseImageList(value) {
  const parsed = parseJSON(value, []);

  if (Array.isArray(parsed)) {
    return parsed.filter(
      (item) => typeof item === "string" && item.trim()
    );
  }

  if (typeof parsed === "string" && parsed.trim()) {
    return [parsed];
  }

  return [];
}

function jsonValue(value, fallback = []) {
  if (value === undefined || value === null || value === "") {
    return JSON.stringify(fallback);
  }

  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value));
    } catch {
      return JSON.stringify(value);
    }
  }

  return JSON.stringify(value);
}

function getNumber(value, fallback = 0) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  const number = Number(value);

  return Number.isFinite(number) ? number : NaN;
}

function deleteOldImage(imagePath) {
  if (!imagePath) return;
  if (/^https?:\/\//i.test(imagePath)) return;

  const cleanPath = String(imagePath)
    .split("?")[0]
    .replace(/\\/g, "/");

  const filename = path.basename(cleanPath);
  if (!filename) return;

  const fullPath = path.join(uploadDir, filename);

  if (fs.existsSync(fullPath)) {
    fs.unlink(fullPath, (err) => {
      if (err) {
        console.error("OLD IMAGE DELETE ERROR:", err);
      }
    });
  }
}

function deleteUploadedFiles(files = []) {
  files.forEach((file) => {
    if (file?.path && fs.existsSync(file.path)) {
      fs.unlink(file.path, () => {});
    }
  });
}

function getUploadedImagePaths(files = []) {
  return files.map(
    (file) => `uploads/products/${file.filename}`
  );
}

// ======================================================
// CATEGORY CODE
// ======================================================

function getCategoryCode(categoryName) {
  const words = String(categoryName || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (!words.length) return "X";

  return words[0][0]
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "X");
}

// ======================================================
// SUBCATEGORY CODE
// ======================================================

function getSubcategoryCode(subcategoryName) {
  const words = String(subcategoryName || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (!words.length) return "XX";

  if (words.length === 1) {
    return (
      words[0]
        .replace(/[^a-zA-Z0-9]/g, "")
        .substring(0, 2)
        .toUpperCase() || "XX"
    );
  }

  return words
    .map((word) => word[0])
    .join("")
    .replace(/[^A-Z0-9]/gi, "")
    .toUpperCase();
}

// ======================================================
// SKU GENERATOR
// FORMAT: HWC-2-001
// ======================================================

async function generateSku(
  connection,
  categoryName,
  subcategoryName,
  subcategoryId
) {
  const categoryCode = getCategoryCode(categoryName);
  const subcategoryCode = getSubcategoryCode(subcategoryName);

  const prefix = `${categoryCode}${subcategoryCode}-${subcategoryId}-`;

  const [rows] = await connection.query(
    `SELECT sku_code
     FROM products
     WHERE sku_code LIKE ?
     ORDER BY sku_code DESC
     LIMIT 1
     FOR UPDATE`,
    [`${prefix}%`]
  );

  let nextNumber = 1;

  if (rows.length && rows[0].sku_code) {
    const match = String(rows[0].sku_code).match(/-(\d+)$/);

    if (match) {
      nextNumber = Number(match[1]) + 1;
    }
  }

  let sku = `${prefix}${String(nextNumber).padStart(3, "0")}`;

  while (true) {
    const [duplicate] = await connection.query(
      "SELECT id FROM products WHERE sku_code = ? LIMIT 1",
      [sku]
    );

    if (!duplicate.length) break;

    nextNumber += 1;
    sku = `${prefix}${String(nextNumber).padStart(3, "0")}`;
  }

  return sku;
}

// ======================================================
// VALIDATE VENDOR
// ======================================================

async function validateVendor(connection, vendorId) {
  if (
    vendorId === undefined ||
    vendorId === null ||
    vendorId === "" ||
    !/^\d+$/.test(String(vendorId))
  ) {
    return null;
  }

  const [rows] = await connection.query(
    `SELECT id, vendor_name
     FROM vendors
     WHERE id = ? AND status = 'active'
     LIMIT 1`,
    [Number(vendorId)]
  );

  return rows.length ? rows[0] : null;
}

// ======================================================
// PRODUCT RESPONSE FORMAT
// ======================================================

function formatProduct(product) {
  if (!product) return product;

  return {
    ...product,

    sku: product.sku_code || "",

    selling_price: product.price,

    price: product.price,

    wholesale_price: product.wholesale_price ?? 0,

    vendor_name: product.vendor_name || null,

    images: parseImageList(product.product_images),

    colors: parseJSON(product.colors, []),

    sizes: parseJSON(product.sizes, []),

    sections: parseJSON(product.sections, []),
  };
}

// ======================================================
// PRODUCT SELECT WITH VENDOR
// ======================================================

const PRODUCT_SELECT = `
  SELECT
    p.*,
    v.vendor_name
  FROM products p
  LEFT JOIN vendors v ON v.id = p.vendor_id
`;

// ======================================================
// GET PRODUCTS BY CATEGORY / SUBCATEGORY
// GET /api/product/skus
// ======================================================

router.get("/skus", async (req, res) => {
  try {
    const { category_id, subcategory_id } = req.query;

    if (!subcategory_id || !/^\d+$/.test(String(subcategory_id))) {
      return res.status(400).json({
        success: false,
        message: "Valid subcategory_id is required",
      });
    }

    let sql = `
      SELECT
        id,
        product_name,
        category_id,
        subcategory_id,
        vendor_id,
        category_name,
        subcategory_name,
        sku_code,
        product_status
      FROM products
      WHERE subcategory_id = ?
    `;

    const params = [Number(subcategory_id)];

    if (category_id !== undefined && category_id !== "") {
      if (!/^\d+$/.test(String(category_id))) {
        return res.status(400).json({
          success: false,
          message: "Invalid category_id",
        });
      }

      sql += " AND category_id = ?";
      params.push(Number(category_id));
    }

    sql += " ORDER BY id ASC";

    const [products] = await pool.query(sql, params);

    return res.json({
      success: true,
      count: products.length,
      products: products.map(formatProduct),
    });
  } catch (err) {
    console.error("FETCH CATEGORY SKU ERROR:", err);

    return res.status(500).json({
      success: false,
      message: "SKU fetch failed",
      error: err.message,
    });
  }
});

// ======================================================
// GET ALL PRODUCTS
// GET /api/product
// ======================================================

router.get("/", async (req, res) => {
  try {
    const [products] = await pool.query(
      `${PRODUCT_SELECT} ORDER BY p.id DESC`
    );

    return res.json({
      success: true,
      count: products.length,
      products: products.map(formatProduct),
    });
  } catch (err) {
    console.error("GET PRODUCTS ERROR:", err);

    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});

// ======================================================
// ADD PRODUCT
// POST /api/product
// MULTIPART FORM DATA
// ======================================================

router.post("/", upload.array("product_image", 4), async (req, res) => {
  let connection;

  const uploadedFiles = req.files || [];

  try {
    const {
      product_name,
      category_id,
      subcategory_id,
      vendor_id,
      category_name,
      brand_name,
      mrp,
      product_status,
    } = req.body;

    const priceInput =
      req.body.price !== undefined
        ? req.body.price
        : req.body.selling_price;

    const descriptionInput =
      req.body.description !== undefined
        ? req.body.description
        : req.body.product_description;

    if (!String(product_name || "").trim()) {
      return res.status(400).json({
        success: false,
        message: "Product name is required",
      });
    }

    if (!category_id || !/^\d+$/.test(String(category_id))) {
      return res.status(400).json({
        success: false,
        message: "Valid category is required",
      });
    }

    if (!subcategory_id || !/^\d+$/.test(String(subcategory_id))) {
      return res.status(400).json({
        success: false,
        message: "Valid subcategory ID is required for SKU generation",
      });
    }

    if (!vendor_id || !/^\d+$/.test(String(vendor_id))) {
      return res.status(400).json({
        success: false,
        message: "Please select a vendor",
      });
    }

    const priceValue = getNumber(priceInput);
    const wholesaleValue = getNumber(req.body.wholesale_price);
    const mrpValue = getNumber(mrp);
    const stockValue = getNumber(
      req.body.stock_quantity !== undefined
        ? req.body.stock_quantity
        : req.body.stock
    );

    if (
      !Number.isFinite(priceValue) ||
      !Number.isFinite(wholesaleValue) ||
      !Number.isFinite(mrpValue) ||
      !Number.isInteger(stockValue) ||
      priceValue < 0 ||
      wholesaleValue < 0 ||
      mrpValue < 0 ||
      stockValue < 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid price or stock quantity",
      });
    }

    if (mrpValue > 0 && priceValue > mrpValue) {
      return res.status(400).json({
        success: false,
        message: "Selling price MRP se zyada nahi ho sakta",
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Validate vendor
    const vendor = await validateVendor(connection, vendor_id);

    if (!vendor) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message: "Selected vendor not found or inactive",
      });
    }

    // Validate category
    const [categoryRows] = await connection.query(
      `SELECT id, category_name
       FROM categories
       WHERE id = ?
       LIMIT 1`,
      [Number(category_id)]
    );

    if (!categoryRows.length) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message: "Category ID not found",
      });
    }

    // Validate subcategory
    const [subcategoryRows] = await connection.query(
      `SELECT id, subcategory_name, category_id
       FROM subcategories
       WHERE id = ? AND category_id = ?
       LIMIT 1`,
      [Number(subcategory_id), Number(category_id)]
    );

    if (!subcategoryRows.length) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message: "Subcategory does not belong to selected category",
      });
    }

    const actualCategoryName = categoryRows[0].category_name;
    const actualSubcategoryName =
      subcategoryRows[0].subcategory_name;

    const sku = await generateSku(
      connection,
      actualCategoryName,
      actualSubcategoryName,
      Number(subcategory_id)
    );

    const imagePaths = getUploadedImagePaths(uploadedFiles);
    const primaryImage = imagePaths[0] || null;

    const [result] = await connection.query(
      `INSERT INTO products (
        category_id,
        subcategory_id,
        vendor_id,
        product_name,
        sku_code,
        category_name,
        subcategory_name,
        brand_name,
        product_description,
        price,
        wholesale_price,
        mrp,
        stock_quantity,
        product_image,
        product_images,
        primary_image_index,
        colors,
        sizes,
        sections,
        product_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        Number(category_id),
        Number(subcategory_id),
        Number(vendor_id),
        String(product_name).trim(),
        sku,
        actualCategoryName,
        actualSubcategoryName,
        brand_name || null,
        descriptionInput || null,
        priceValue,
        wholesaleValue,
        mrpValue,
        stockValue,
        primaryImage,
        JSON.stringify(imagePaths),
        0,
        jsonValue(req.body.colors),
        jsonValue(req.body.sizes),
        jsonValue(req.body.sections),
        product_status === "inactive" ? "inactive" : "active",
      ]
    );

    const [savedRows] = await connection.query(
      `${PRODUCT_SELECT} WHERE p.id = ?`,
      [result.insertId]
    );

    await connection.commit();

    return res.status(201).json({
      success: true,
      message: "Product added successfully",
      sku_code: sku,
      sku,
      product: formatProduct(savedRows[0]),
    });
  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (_) {}
    }

    deleteUploadedFiles(uploadedFiles);

    console.error("ADD PRODUCT ERROR:", err);

    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        success: false,
        message: "Duplicate SKU detected. Please retry.",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Product add failed",
      error: err.message,
    });
  } finally {
    if (connection) connection.release();
  }
});

// ======================================================
// GET SINGLE PRODUCT
// GET /api/product/:id
// ======================================================

router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID",
      });
    }

    const [rows] = await pool.query(
      `${PRODUCT_SELECT} WHERE p.id = ? LIMIT 1`,
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    return res.json({
      success: true,
      product: formatProduct(rows[0]),
    });
  } catch (err) {
    console.error("GET PRODUCT ERROR:", err);

    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});

// ======================================================
// UPDATE PRODUCT
// PUT /api/product/:id
// ======================================================

router.put("/:id", upload.array("product_image", 4), async (req, res) => {
  const uploadedFiles = req.files || [];

  try {
    const { id } = req.params;

    if (!/^\d+$/.test(id)) {
      deleteUploadedFiles(uploadedFiles);

      return res.status(400).json({
        success: false,
        message: "Invalid product ID",
      });
    }

    const [rows] = await pool.query(
      "SELECT * FROM products WHERE id = ? LIMIT 1",
      [id]
    );

    if (!rows.length) {
      deleteUploadedFiles(uploadedFiles);

      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    const oldProduct = rows[0];

    const sets = [];
    const values = [];

    const fieldMap = {
      product_name: "product_name",
      brand_name: "brand_name",
      mrp: "mrp",
      product_status: "product_status",
    };

    for (const [frontendField, dbColumn] of Object.entries(fieldMap)) {
      if (req.body[frontendField] !== undefined) {
        sets.push(`\`${dbColumn}\` = ?`);
        values.push(req.body[frontendField]);
      }
    }

    // Accept both price field names
    if (
      req.body.price !== undefined ||
      req.body.selling_price !== undefined
    ) {
      const price = getNumber(
        req.body.price !== undefined
          ? req.body.price
          : req.body.selling_price
      );

      if (!Number.isFinite(price) || price < 0) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Invalid selling price",
        });
      }

      sets.push("price = ?");
      values.push(price);
    }

    // Wholesale price
    if (req.body.wholesale_price !== undefined) {
      const wholesale = getNumber(req.body.wholesale_price);

      if (!Number.isFinite(wholesale) || wholesale < 0) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Invalid wholesale price",
        });
      }

      sets.push("wholesale_price = ?");
      values.push(wholesale);
    }

    // Stock
    if (
      req.body.stock_quantity !== undefined ||
      req.body.stock !== undefined
    ) {
      const stock = getNumber(
        req.body.stock_quantity !== undefined
          ? req.body.stock_quantity
          : req.body.stock
      );

      if (!Number.isInteger(stock) || stock < 0) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Invalid stock quantity",
        });
      }

      sets.push("stock_quantity = ?");
      values.push(stock);
    }

    // Description
    if (
      req.body.description !== undefined ||
      req.body.product_description !== undefined
    ) {
      sets.push("product_description = ?");
      values.push(
        req.body.description !== undefined
          ? req.body.description
          : req.body.product_description
      );
    }

    // Category and subcategory
    if (req.body.category_id !== undefined) {
      if (
        req.body.category_id &&
        !/^\d+$/.test(String(req.body.category_id))
      ) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Invalid category ID",
        });
      }

      sets.push("category_id = ?");
      values.push(req.body.category_id || null);
    }

    if (req.body.subcategory_id !== undefined) {
      if (
        req.body.subcategory_id &&
        !/^\d+$/.test(String(req.body.subcategory_id))
      ) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Invalid subcategory ID",
        });
      }

      sets.push("subcategory_id = ?");
      values.push(req.body.subcategory_id || null);
    }

    // Vendor
    if (req.body.vendor_id !== undefined) {
      if (
        !req.body.vendor_id ||
        !/^\d+$/.test(String(req.body.vendor_id))
      ) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Please select a valid vendor",
        });
      }

      const vendor = await validateVendor(pool, req.body.vendor_id);

      if (!vendor) {
        deleteUploadedFiles(uploadedFiles);

        return res.status(400).json({
          success: false,
          message: "Selected vendor not found or inactive",
        });
      }

      sets.push("vendor_id = ?");
      values.push(Number(req.body.vendor_id));
    }

    // Validate product name
    if (
      req.body.product_name !== undefined &&
      !String(req.body.product_name).trim()
    ) {
      deleteUploadedFiles(uploadedFiles);

      return res.status(400).json({
        success: false,
        message: "Product name is required",
      });
    }

    const nextMrp = getNumber(
      req.body.mrp !== undefined
        ? req.body.mrp
        : oldProduct.mrp
    );

    const nextPrice = getNumber(
      req.body.price !== undefined
        ? req.body.price
        : req.body.selling_price !== undefined
        ? req.body.selling_price
        : oldProduct.price
    );

    if (
      !Number.isFinite(nextMrp) ||
      !Number.isFinite(nextPrice) ||
      nextMrp < 0 ||
      nextPrice < 0
    ) {
      deleteUploadedFiles(uploadedFiles);

      return res.status(400).json({
        success: false,
        message: "Invalid price or MRP",
      });
    }

    if (nextMrp > 0 && nextPrice > nextMrp) {
      deleteUploadedFiles(uploadedFiles);

      return res.status(400).json({
        success: false,
        message: "Selling price MRP se zyada nahi ho sakta",
      });
    }

    // Colors, sizes and sections
    ["colors", "sizes", "sections"].forEach((field) => {
      if (req.body[field] !== undefined) {
        sets.push(`\`${field}\` = ?`);
        values.push(jsonValue(req.body[field]));
      }
    });

    // Existing images sent by frontend.
    // If omitted, old images remain unchanged.
    let finalImages = parseImageList(oldProduct.product_images);

    if (!finalImages.length && oldProduct.product_image) {
      finalImages = [oldProduct.product_image];
    }

    if (req.body.existing_images !== undefined) {
      finalImages = parseImageList(req.body.existing_images);
    }

    const newImagePaths = getUploadedImagePaths(uploadedFiles);

    finalImages = [
      ...finalImages,
      ...newImagePaths,
    ].slice(0, 4);

    if (
      req.body.existing_images !== undefined ||
      uploadedFiles.length > 0
    ) {
      sets.push("product_images = ?");
      values.push(JSON.stringify(finalImages));

      sets.push("product_image = ?");
      values.push(finalImages[0] || null);

      sets.push("primary_image_index = ?");
      values.push(0);
    }

    if (!sets.length) {
      deleteUploadedFiles(uploadedFiles);

      return res.status(400).json({
        success: false,
        message: "No changes received",
      });
    }

    values.push(id);

    await pool.query(
      `UPDATE products
       SET ${sets.join(", ")}
       WHERE id = ?`,
      values
    );

    // Delete images removed by frontend
    const oldImages = parseImageList(oldProduct.product_images);

    if (!oldImages.length && oldProduct.product_image) {
      oldImages.push(oldProduct.product_image);
    }

    const removedImages = oldImages.filter(
      (image) => !finalImages.includes(image)
    );

    removedImages.forEach(deleteOldImage);

    const [updatedRows] = await pool.query(
      `${PRODUCT_SELECT} WHERE p.id = ? LIMIT 1`,
      [id]
    );

    return res.json({
      success: true,
      message: "Product successfully updated",
      product: formatProduct(updatedRows[0]),
    });
  } catch (err) {
    deleteUploadedFiles(uploadedFiles);

    console.error("UPDATE PRODUCT ERROR:", err);

    return res.status(500).json({
      success: false,
      message: "Product update failed",
      error: err.message,
    });
  }
});

// ======================================================
// UPDATE PRODUCT STATUS
// PATCH /api/product/:id/status
// ======================================================

router.patch("/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { product_status } = req.body;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid product ID",
      });
    }

    if (!["active", "inactive"].includes(product_status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be active or inactive",
      });
    }

    const [result] = await pool.query(
      `UPDATE products
       SET product_status = ?
       WHERE id = ?`,
      [product_status, id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    return res.json({
      success: true,
      message: "Product status updated successfully",
      product_status,
    });
  } catch (err) {
    console.error("PRODUCT STATUS ERROR:", err);

    return res.status(500).json({
      success: false,
      message: "Product status update failed",
      error: err.message,
    });
  }
});

// ======================================================
// MULTER ERROR HANDLER
// ======================================================

router.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      message:
        err.code === "LIMIT_FILE_SIZE"
          ? "Image 5MB se choti honi chahiye"
          : err.code === "LIMIT_FILE_COUNT"
          ? "Maximum 4 images allowed"
          : err.message,
    });
  }

  if (err) {
    return res.status(400).json({
      success: false,
      message: err.message,
    });
  }

  next();
});

module.exports = router;
