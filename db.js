import mysql from "mysql2/promise";

export const pool = mysql.createPool({
  host: "127.0.0.1",
  user: "root",
  password: "1234", // รหัส MySQL XAMPP
  database: "worklog_db",
  timezone: "+07:00"  // ✅ ตั้งค่า timezone ไทย
});
