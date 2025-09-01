// ==============================
// 📦 Import Modules ที่ต้องใช้
// ==============================
import express from "express";      // Framework สำหรับสร้าง API
import cors from "cors";            // อนุญาตให้ React (Frontend) เข้าถึง API
import { pool } from "./db.js";     // การเชื่อมต่อ MySQL
import jwt from "jsonwebtoken";     // สร้าง/ตรวจสอบ Token
import bcrypt from "bcryptjs";      // เข้ารหัส/ตรวจสอบรหัสผ่าน

const app = express();

// ==============================
// ⚙️ Middleware หลัก
// ==============================
// อนุญาตให้ frontend เรียก API ได้ (กำหนด origin ให้ตรงกับ React)
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
// อ่านข้อมูล JSON ใน request body
app.use(express.json());

// คีย์ลับสำหรับสร้าง/ตรวจสอบ JWT Token
const JWT_SECRET = "secret123";

// ==============================
// 🔑 Middleware ตรวจสอบ Token
// ==============================
// ใช้ใน API ที่ต้องล็อกอินเท่านั้น
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token" });
  }
  try {
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // เก็บข้อมูล user id / role ไว้ใช้ต่อ
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

//
// ==============================
// 👤 AUTHENTICATION APIs
// ==============================
//

// --- Login ---
// 📌 ใช้โดย: Login.jsx
// ตรวจสอบผู้ใช้ → ตรวจรหัสผ่าน → สร้าง token ส่งกลับ
app.post("/api/login", async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: "Missing fields" });

  const [rows] = await pool.query(
    "SELECT * FROM users WHERE email = ? OR student_code = ? LIMIT 1",
    [login, login]
  );
  if (rows.length === 0) return res.status(401).json({ error: "User not found" });

  const user = rows[0];
  if (user.account_status !== "active") {
    return res.status(403).json({ error: "Account inactive" });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });

  res.json({
    token,
    user: {
      id: user.user_id,
      student_code: user.student_code,
      fullname: user.fullname,
      email: user.email,
      role: user.role
    }
  });
});

// --- Get current user info ---
// 📌 ใช้โดย: หน้า Dashboard หรือ Navbar หลังล็อกอิน
// ดึงข้อมูล user ตาม token
app.get("/api/me", authMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT user_id, student_code, fullname, email, university, phone, room, role, account_status FROM users WHERE user_id = ?",
    [req.user.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: "User not found" });
  res.json({ user: rows[0] });
});

// --- Register ---
// 📌 ใช้โดย: Register.jsx
// สมัครสมาชิกใหม่
app.post("/api/register", async (req, res) => {
  const { student_code, fullname, university, phone, room, email, password } = req.body;
  if (!student_code || !fullname || !email || !password) {
    return res.status(400).json({ error: "กรอกข้อมูลให้ครบ" });
  }

  const [exists] = await pool.query(
    "SELECT user_id FROM users WHERE email = ? OR student_code = ? LIMIT 1",
    [email, student_code]
  );
  if (exists.length > 0) {
    return res.status(409).json({ error: "อีเมลหรือรหัสนักศึกษาใช้แล้ว" });
  }

  const hashed = await bcrypt.hash(password, 10);
  await pool.query(
    `INSERT INTO users 
     (student_code, fullname, university, phone, room, email, password_hash, role, account_status) 
     VALUES (?, ?, ?, ?, ?, ?, ?, 'student', 'active')`,
    [student_code, fullname, university || null, phone || null, room || null, email, hashed]
  );
  res.json({ message: "สมัครสมาชิกสำเร็จ" });
});

//
// ==============================
// 📝 STUDENT APIs
// ==============================
//

// --- Get daily logs (ของตัวเอง) ---
// 📌 ใช้โดย: DailyLogs.jsx / DailyLogStatus.jsx
app.get("/api/daily-logs", authMiddleware, async (req, res) => {
  try {
    const [logs] = await pool.query(
      `SELECT log_id, log_date, activity, status, approved_by, created_at, updated_at
       FROM daily_logs 
       WHERE user_id = ?
       ORDER BY log_date DESC`,
      [req.user.id]
    );
    res.json({ logs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
  }
});



// --- Add daily log ---
// 📌 ใช้โดย: DailyLogs.jsx
// ป้องกันวันอนาคตและวันซ้ำ
app.post("/api/daily-logs", authMiddleware, async (req, res) => {
  const { log_date, activity } = req.body;
  if (!log_date || !activity) {
    return res.status(400).json({ error: "กรอกข้อมูลไม่ครบ" });
  }

  const today = new Date().toISOString().split("T")[0];
  if (log_date > today) {
    return res.status(400).json({ error: "ไม่สามารถเลือกวันที่อนาคตได้" });
  }

  try {
    const [exists] = await pool.query(
      `SELECT log_id FROM daily_logs WHERE user_id = ? AND log_date = ? LIMIT 1`,
      [req.user.id, log_date]
    );
    if (exists.length > 0) {
      return res.status(400).json({ error: "มีบันทึกของวันนี้แล้ว" });
    }

    await pool.query(
      `INSERT INTO daily_logs (user_id, log_date, activity, status) 
       VALUES (?, ?, ?, 'pending')`,
      [req.user.id, log_date, activity]
    );
    res.json({ message: "บันทึกสำเร็จ" });
  } catch {
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการบันทึก" });
  }
});

// --- Student report ---
// 📌 ใช้โดย: StudentReport.jsx และ Dashboard.jsx
app.get("/api/student-report", authMiddleware, async (req, res) => {
  try {
    const { date, keyword } = req.query;
    let sql = `
      SELECT dl.log_date, dl.created_at, dl.updated_at, 
             dl.activity, dl.status, dl.approved_by,
             u.student_code, u.fullname
      FROM daily_logs dl
      JOIN users u ON dl.user_id = u.user_id
      WHERE dl.user_id = ?
    `;
    const params = [req.user.id];

    if (date) {
      sql += ` AND dl.log_date = ?`;
      params.push(date);
    }
    if (keyword) {
      sql += ` AND dl.activity LIKE ?`;
      params.push(`%${keyword}%`);
    }

    sql += ` ORDER BY dl.log_date DESC`;

    const [logs] = await pool.query(sql, params);

    const summary = {
      total: logs.length,
      approved: logs.filter(log => log.status === "approved").length,
      pending: logs.filter(log => log.status === "pending").length,
      rejected: logs.filter(log => log.status === "rejected").length
    };

    res.json({ summary, logs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลรายงาน" });
  }
});



// --- Edit own daily log ---
// 📌 ใช้โดย: DailyLogStatus.jsx
// แก้ไขได้เฉพาะสถานะ pending
app.put("/api/daily-logs/:id", authMiddleware, async (req, res) => {
  const { activity } = req.body;
  if (!activity || !activity.trim()) {
    return res.status(400).json({ error: "กรุณากรอกรายละเอียดงาน" });
  }

  try {
    const [result] = await pool.query(
      `UPDATE daily_logs 
       SET activity = ?, updated_at = CONVERT_TZ(NOW(), '+00:00', '+07:00')
       WHERE log_id = ? 
         AND user_id = ? 
         AND status = 'pending'`,
      [activity.trim(), req.params.id, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ไม่พบข้อมูล หรือไม่สามารถแก้ไขได้" });
    }

    // ✅ ดึงข้อมูลล่าสุดกลับมาให้ frontend ใช้ต่อ
    const [rows] = await pool.query(
      `SELECT log_id, log_date, activity, status, approved_by, created_at, updated_at
       FROM daily_logs
       WHERE log_id = ? AND user_id = ?`,
      [req.params.id, req.user.id]
    );

    res.json({ message: "แก้ไขบันทึกงานสำเร็จ", log: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาด" });
  }
});


//
// ==============================
// 🛠 ADMIN APIs
// ==============================
//

// --- Get all logs ---
// 📌 ใช้โดย: AdminDailyLogs.jsx
app.get("/api/daily-logs-all", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") 
    return res.status(403).json({ error: "ไม่มีสิทธิ์เข้าถึง" });

  // ✅ ใช้ status filter แทน approved_by
  const { date, name, university, status } = req.query;  
  let sql = `
    SELECT dl.log_id, dl.log_date, dl.activity, dl.status, dl.created_at, dl.updated_at,
           u.fullname AS fullname, u.university AS university, dl.approved_by
    FROM daily_logs dl
    JOIN users u ON dl.user_id = u.user_id
    WHERE u.role = 'student'
  `;
  const params = [];

  if (date) { 
    sql += " AND dl.log_date = ?"; 
    params.push(date); 
  }
  if (name) { 
    sql += " AND u.fullname LIKE ?"; 
    params.push(`%${name}%`); 
  }
  if (university) {  
    sql += " AND u.university LIKE ?"; 
    params.push(`%${university}%`); 
  }
  if (status) {  
    sql += " AND dl.status = ?"; 
    params.push(status); 
  }

  sql += " ORDER BY dl.log_date DESC";

  try {
    const [logs] = await pool.query(sql, params);

    const [universities] = await pool.query(`
      SELECT DISTINCT university 
      FROM users 
      WHERE university IS NOT NULL 
        AND university <> '' 
        AND role = 'student'
      ORDER BY university ASC
    `);

    res.json({ 
      logs,
      universities: universities.map(u => u.university)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
  }
});




// --- Update log status ---
// 📌 ใช้โดย: AdminDailyLogs.jsx
app.put("/api/daily-logs/:id/status", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "ไม่มีสิทธิ์" });

  const { status, approved_by } = req.body;
  if (!['pending', 'approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  if (!approved_by || !approved_by.trim()) {
    return res.status(400).json({ error: "กรุณากรอกชื่อผู้อนุมัติ" });
  }

  try {
    await pool.query(
      `UPDATE daily_logs 
       SET status = ?, approved_by = ?, updated_at = NOW()
       WHERE log_id = ?`,
      [status, approved_by.trim(), req.params.id]
    );
    res.json({ message: "อัปเดตสถานะสำเร็จ" });
  } catch {
    res.status(500).json({ error: "เกิดข้อผิดพลาด" });
  }
});

// --- Admin student report ---
// 📌 ใช้โดย: AdminStudentReport.jsx
app.get("/api/admin/student-report", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "ไม่มีสิทธิ์เข้าถึง" });

  const { date, name, student_code, university } = req.query;
  let params = [];
  let where = "";

  if (date) {
    where += " AND dl.log_date = ?";
    params.push(date);
  }
  if (name) {
    where += " AND u.fullname LIKE ?";
    params.push(`%${name}%`);
  }
  if (student_code) {
    where += " AND u.student_code LIKE ?";
    params.push(`%${student_code}%`);
  }
  if (university) {
    where += " AND u.university LIKE ?";
    params.push(`%${university}%`);
  }

  // ดึงข้อมูล log + user
  const [rows] = await pool.query(`
    SELECT u.user_id, u.fullname, u.student_code, u.university,
           dl.log_id, dl.log_date, dl.activity, dl.status, dl.approved_by
    FROM daily_logs dl
    JOIN users u ON dl.user_id = u.user_id
    WHERE 1=1 ${where}
    ORDER BY u.student_code, dl.log_date DESC
  `, params);

  // Group ข้อมูลตามนักศึกษา
  const reportMap = {};
  rows.forEach(row => {
    if (!reportMap[row.student_code]) {
      reportMap[row.student_code] = {
        fullname: row.fullname,
        student_code: row.student_code,
        university: row.university,
        approved: 0,
        rejected: 0,
        pending: 0,
        total: 0,
        logs: []
      };
    }

    if (row.status === "approved") reportMap[row.student_code].approved++;
    else if (row.status === "rejected") reportMap[row.student_code].rejected++;
    else if (row.status === "pending") reportMap[row.student_code].pending++;

    reportMap[row.student_code].total++;
    reportMap[row.student_code].logs.push(row);
  });

  // ✅ ดึงลิสต์มหาลัยทั้งหมด
  const [uniRows] = await pool.query(`
    SELECT DISTINCT university FROM users WHERE role = 'student'
  `);

  res.json({
    reports: Object.values(reportMap),
    universities: uniRows.map(u => u.university)
  });
});


// --- Update profile ---
app.put("/api/profile", authMiddleware, async (req, res) => {
  const { fullname, university, phone, room } = req.body;

  try {
    await pool.query(
      `UPDATE users 
       SET fullname = ?, university = ?, phone = ?, room = ?, updated_at = NOW()
       WHERE user_id = ? AND role = 'student'`,
      [fullname, university, phone, room, req.user.id]
    );

    res.json({ message: "แก้ไขโปรไฟล์สำเร็จ" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "เกิดข้อผิดพลาด" });
  }
});






//
// ==============================
// 🚀 START SERVER
// ==============================
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
