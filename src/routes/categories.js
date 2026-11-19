
const express = require("express");
const router = express.Router();
const pool = require("./pool");

// ========================================
// GET ALL CATEGORIES WITH SUBCATEGORIES
// GET /api/categories
// ========================================
router.get("/", async (req, res) => {
  try {
    const [categories] = await pool.execute(`
      SELECT
        c.id,
        c.category_name,
        c.category_status
      FROM categories c
      WHERE c.category_status = 'active'
      ORDER BY c.id DESC
    `);

    const [subcategories] = await pool.execute(`
      SELECT
        s.id,
        s.category_id,
        s.subcategory_name,
        s.subcategory_status
      FROM subcategories s
      WHERE s.subcategory_status = 'active'
      ORDER BY s.id DESC
    `);

    const formattedCategories = categories.map((category) => ({
      ...category,
      subcategories: subcategories.filter(
        (sub) => Number(sub.category_id) === Number(category.id)
      ),
    }));

    return res.json({
      success: true,
      categories: formattedCategories,
    });
  } catch (error) {
    console.error("Get categories error:", error);

    return res.status(500).json({
      success: false,
      message: "Categories fetch nahi hui.",
      error: error.message,
    });
  }
});

// ========================================
// ADD CATEGORY
// POST /api/categories
// Body: { category_name }
// ========================================
router.post("/", async (req, res) => {
  try {
    const categoryName = String(
      req.body.category_name || ""
    ).trim();

    if (!categoryName) {
      return res.status(400).json({
        success: false,
        message: "Category name required hai.",
      });
    }

    const [existing] = await pool.execute(
      `SELECT id FROM categories
       WHERE LOWER(category_name) = LOWER(?)
       LIMIT 1`,
      [categoryName]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Ye category pehle se available hai.",
      });
    }

    const [result] = await pool.execute(
      `INSERT INTO categories (category_name, category_status)
       VALUES (?, 'active')`,
      [categoryName]
    );

    return res.status(201).json({
      success: true,
      message: "Category successfully add ho gayi.",
      category: {
        id: result.insertId,
        category_name: categoryName,
      },
    });
  } catch (error) {
    console.error("Add category error:", error);

    return res.status(500).json({
      success: false,
      message: "Category add nahi hui.",
      error: error.message,
    });
  }
});

// ========================================
// ADD SUBCATEGORY
// POST /api/categories/subcategory
// Body: { category_id, subcategory_name }
// ========================================
router.post("/subcategory", async (req, res) => {
  try {
    const categoryId = Number(req.body.category_id);
    const subcategoryName = String(
      req.body.subcategory_name || ""
    ).trim();

    if (!Number.isInteger(categoryId) || categoryId < 1) {
      return res.status(400).json({
        success: false,
        message: "Valid category select karein.",
      });
    }

    if (!subcategoryName) {
      return res.status(400).json({
        success: false,
        message: "Subcategory name required hai.",
      });
    }

    const [category] = await pool.execute(
      `SELECT id FROM categories
       WHERE id = ? AND category_status = 'active'
       LIMIT 1`,
      [categoryId]
    );

    if (category.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Category nahi mili.",
      });
    }

    const [existing] = await pool.execute(
      `SELECT id FROM subcategories
       WHERE category_id = ?
       AND LOWER(subcategory_name) = LOWER(?)
       LIMIT 1`,
      [categoryId, subcategoryName]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Ye subcategory pehle se available hai.",
      });
    }

    const [result] = await pool.execute(
      `INSERT INTO subcategories
       (category_id, subcategory_name, subcategory_status)
       VALUES (?, ?, 'active')`,
      [categoryId, subcategoryName]
    );

    return res.status(201).json({
      success: true,
      message: "Subcategory successfully add ho gayi.",
      subcategory: {
        id: result.insertId,
        category_id: categoryId,
        subcategory_name: subcategoryName,
      },
    });
  } catch (error) {
    console.error("Add subcategory error:", error);

    return res.status(500).json({
      success: false,
      message: "Subcategory add nahi hui.",
      error: error.message,
    });
  }
});

module.exports = router;
