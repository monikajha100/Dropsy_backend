const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");
const pool = require("./pool");

//onst pool = require("../config/db"); // ADJUST: aapki mysql2 pool file (.promise() wali)

const BLUE = "#11A7E6";
const ORANGE = "#F59A1B";
const DARK = "#1F2937";
const MUTED = "#6B7280";
const LINE = "#E5E7EB";

const INVOICE_DIR = path.join(__dirname, "..", "..", "uploads", "invoices");
const LOGO_PATH = path.join(__dirname, "..", "..", "assets", "logo.png");

// pdfkit ke default font me ₹ glyph nahi hota, isliye "Rs."
const inr = (n) =>
  "Rs. " +
  Number(n || 0).toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

const fmtDate = (d) =>
  new Date(d).toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" });

// ---------- DB se saari details ----------
async function loadProductData(productId) {
  // ADJUST: table / column names
  const [rows] = await pool.query(
    `SELECT p.*,
            s.full_name AS seller_name,
            s.enrollment_number AS seller_enrollment,
            s.gstin AS seller_gstin
       FROM seller_products p
       JOIN sellers s ON s.id = p.seller_id
      WHERE p.id = ? LIMIT 1`,
    [productId]
  );

  if (!rows.length) throw new Error("Product not found");
  const p = rows[0];

  const price = Number(p.selling_price ?? p.price ?? 0);
  const qty = Number(p.stock_quantity ?? p.stock ?? 0);
  const gstPercent = Number(p.gst_percent ?? p.gst ?? 0);
  const taxable = price * qty;
  const gstAmount = (taxable * gstPercent) / 100;

  return {
    sellerId: p.seller_id,
    sellerName: p.seller_name || "",
    enrollment: p.seller_enrollment || "",
    gstin: p.seller_gstin || "",
    productId: p.id,
    productName: p.product_name || p.title || p.name || "",
    sku: p.sku || p.sku_code || "",
    category: p.category_name || p.category || "",
    price,
    qty,
    gstPercent,
    taxable,
    gstAmount,
    total: taxable + gstAmount,
  };
}

// ---------- PDF draw ----------
function renderPdf(filePath, d, inv) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(INVOICE_DIR, { recursive: true });

    const doc = new PDFDocument({ size: "A4", margin: 40 });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);
    stream.on("finish", resolve);
    stream.on("error", reject);

    const L = 40;
    const R = 555;
    const W = R - L;

    // top color bar
    doc.rect(0, 0, 595, 10).fill(BLUE);
    doc.rect(400, 0, 195, 10).fill(ORANGE);

    // logo + company
    let textX = L;
    if (fs.existsSync(LOGO_PATH)) {
      doc.image(LOGO_PATH, L, 28, { fit: [90, 50] });
      textX = L + 100;
    }

    doc.fillColor(DARK).font("Helvetica-Bold").fontSize(17)
      .text(process.env.COMPANY_NAME || "Dropshy", textX, 30);
    doc.font("Helvetica").fontSize(8.5).fillColor(MUTED);
    [
      process.env.COMPANY_ADDRESS,
      [process.env.COMPANY_PHONE, process.env.COMPANY_EMAIL].filter(Boolean).join("  |  "),
      process.env.COMPANY_WEBSITE,
      process.env.COMPANY_GSTIN ? `GSTIN: ${process.env.COMPANY_GSTIN}` : "",
    ]
      .filter(Boolean)
      .forEach((line) => doc.text(line, textX, doc.y, { width: 260 }));

    // invoice title
    doc.font("Helvetica-Bold").fontSize(22).fillColor(BLUE)
      .text("INVOICE", 380, 30, { width: R - 380, align: "right" });
    doc.font("Helvetica").fontSize(9).fillColor(MUTED);
    doc.text("Invoice No.", 380, 62, { width: R - 380, align: "right" });
    doc.font("Helvetica-Bold").fontSize(11).fillColor(DARK)
      .text(inv.invoiceNo, 380, 74, { width: R - 380, align: "right" });
    doc.font("Helvetica").fontSize(9).fillColor(MUTED)
      .text(`Date: ${fmtDate(inv.invoiceDate)}`, 380, 92, { width: R - 380, align: "right" });

    doc.moveTo(L, 125).lineTo(R, 125).lineWidth(1.5).strokeColor(ORANGE).stroke();

    // seller block
    doc.font("Helvetica-Bold").fontSize(9).fillColor(BLUE).text("SELLER DETAILS", L, 140);
    const sellerRows = [
      ["Seller Name", d.sellerName],
      ["Enrollment No.", d.enrollment],
      ["GSTIN", d.gstin],
    ];
    let y = 156;
    sellerRows.forEach(([k, v]) => {
      doc.font("Helvetica").fontSize(9).fillColor(MUTED).text(k, L, y, { width: 95 });
      doc.font("Helvetica-Bold").fillColor(DARK).text(v || "-", L + 100, y, { width: 380 });
      y += 16;
    });

    // product table
    const tTop = 225;
    doc.rect(L, tTop, W, 24).fill(BLUE);
    doc.font("Helvetica-Bold").fontSize(8.5).fillColor("#FFFFFF");
    const cols = [
      ["Product", L + 8, 135, "left"],
      ["ID", L + 143, 30, "left"],
      ["SKU", L + 175, 65, "left"],
      ["Category", L + 242, 70, "left"],
      ["Price", L + 314, 60, "right"],
      ["Qty", L + 376, 30, "right"],
      ["GST", L + 408, 40, "right"],
      ["Amount", L + 450, 60, "right"],
    ];
    cols.forEach(([t, x, w, a]) => doc.text(t, x, tTop + 8, { width: w, align: a }));

    const rowY = tTop + 32;
    doc.font("Helvetica").fontSize(8.5).fillColor(DARK);
    const cells = [
      d.productName,
      String(d.productId),
      d.sku || "-",
      d.category || "-",
      inr(d.price),
      String(d.qty),
      `${d.gstPercent}%`,
      inr(d.taxable),
    ];
    cols.forEach(([, x, w, a], i) => doc.text(cells[i], x, rowY, { width: w, align: a }));

    const rowH = Math.max(28, doc.y - rowY + 10);
    doc.moveTo(L, rowY + rowH).lineTo(R, rowY + rowH).lineWidth(0.5).strokeColor(LINE).stroke();

    // totals
    let ty = rowY + rowH + 20;
    const tl = 340;
    const line = (label, value, bold) => {
      doc.font(bold ? "Helvetica-Bold" : "Helvetica").fontSize(bold ? 11 : 9.5)
        .fillColor(bold ? DARK : MUTED).text(label, tl, ty, { width: 110 });
      doc.fillColor(DARK).text(value, tl + 110, ty, { width: R - tl - 110, align: "right" });
      ty += bold ? 22 : 18;
    };
    line("Subtotal", inr(d.taxable));
    line(`GST (${d.gstPercent}%)`, inr(d.gstAmount));
    doc.moveTo(tl, ty - 2).lineTo(R, ty - 2).lineWidth(1).strokeColor(ORANGE).stroke();
    ty += 6;
    line("Total Amount", inr(d.total), true);

    // payment status badge
    const paid = String(inv.paymentStatus).toLowerCase() === "paid";
    doc.roundedRect(L, rowY + rowH + 20, 130, 40, 6).lineWidth(1).strokeColor(paid ? BLUE : ORANGE).stroke();
    doc.font("Helvetica").fontSize(8.5).fillColor(MUTED).text("Payment Status", L + 12, rowY + rowH + 28);
    doc.font("Helvetica-Bold").fontSize(12).fillColor(paid ? BLUE : ORANGE)
      .text(paid ? "PAID" : "PENDING", L + 12, rowY + rowH + 42);

    // signature
    const sy = 700;
    doc.moveTo(380, sy).lineTo(R, sy).lineWidth(0.8).strokeColor(DARK).stroke();
    doc.font("Helvetica-Bold").fontSize(9).fillColor(DARK)
      .text("Authorized Signature", 380, sy + 6, { width: R - 380, align: "center" });
    doc.font("Helvetica").fontSize(8).fillColor(MUTED)
      .text(`For ${process.env.COMPANY_NAME || "Dropshy"}`, 380, sy + 20, { width: R - 380, align: "center" });

    // footer
    doc.rect(0, 822, 595, 20).fill(BLUE);
    doc.font("Helvetica").fontSize(8).fillColor("#FFFFFF")
      .text("This is a computer generated invoice.", 0, 828, { width: 595, align: "center" });

    doc.end();
  });
}

// ---------- main: invoice banao (agar pehle se hai to wahi return) ----------
async function ensureInvoice(productId) {
  const [existing] = await pool.query("SELECT * FROM seller_invoices WHERE product_id = ? LIMIT 1", [productId]);

  if (existing.length && existing[0].pdf_path && fs.existsSync(existing[0].pdf_path)) {
    return { filePath: existing[0].pdf_path, invoiceNo: existing[0].invoice_no };
  }

  const data = await loadProductData(productId);
  let inv = existing[0];

  if (!inv) {
    const temp = `TMP-${Date.now()}-${Math.floor(Math.random() * 1e4)}`;
    const [ins] = await pool.query(
      "INSERT INTO seller_invoices (product_id, seller_id, invoice_no, invoice_date) VALUES (?, ?, ?, CURDATE())",
      [productId, data.sellerId, temp]
    );
    const invoiceNo = `DRP-INV-${new Date().getFullYear()}-${String(ins.insertId).padStart(6, "0")}`;
    await pool.query("UPDATE seller_invoices SET invoice_no = ? WHERE id = ?", [invoiceNo, ins.insertId]);
    const [fresh] = await pool.query("SELECT * FROM seller_invoices WHERE id = ?", [ins.insertId]);
    inv = fresh[0];
  }

  const filePath = path.join(INVOICE_DIR, `${inv.invoice_no}.pdf`);

  await renderPdf(filePath, data, {
    invoiceNo: inv.invoice_no,
    invoiceDate: inv.invoice_date,
    paymentStatus: inv.payment_status,
  });

  await pool.query("UPDATE seller_invoices SET pdf_path = ? WHERE id = ?", [filePath, inv.id]);

  return { filePath, invoiceNo: inv.invoice_no };
}

module.exports = { ensureInvoice };