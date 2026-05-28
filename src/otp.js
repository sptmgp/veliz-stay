const https = require('https');
const bcrypt = require('bcryptjs');
const pool = require('./db');

// Send OTP via MSG91 (India's leading SMS gateway)
async function sendOTP(phone) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const hash = bcrypt.hashSync(otp, 8);
  const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

  // Store OTP hash in DB (never store plain OTP)
  await pool.query(
    `INSERT INTO otp_store (phone, otp_hash, expires_at) VALUES ($1, $2, $3)`,
    [phone, hash, expires]
  );

  if (process.env.NODE_ENV !== 'production' || !process.env.MSG91_AUTH_KEY) {
    // Dev mode — log OTP
    console.log(`[DEV OTP] ${phone}: ${otp}`);
    return { success: true, dev_otp: otp };
  }

  // MSG91 API call
  const payload = JSON.stringify({
    template_id: process.env.MSG91_TEMPLATE_ID,
    mobile: `91${phone.replace(/\D/g, '').slice(-10)}`,
    authkey: process.env.MSG91_AUTH_KEY,
    otp,
  });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'control.msg91.com',
      path: '/api/v5/otp',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        const parsed = JSON.parse(data || '{}');
        resolve({ success: parsed.type === 'success' });
      });
    });
    req.on('error', () => resolve({ success: false }));
    req.write(payload);
    req.end();
  });
}

async function verifyOTP(phone, otp) {
  const rows = await pool.query(
    `SELECT id, otp_hash FROM otp_store
     WHERE phone=$1 AND expires_at > NOW() AND verified=false
     ORDER BY created_at DESC LIMIT 1`,
    [phone]
  );
  if (!rows.rows.length) return false;
  const { id, otp_hash } = rows.rows[0];
  const match = bcrypt.compareSync(otp, otp_hash);
  if (match) {
    await pool.query(`UPDATE otp_store SET verified=true WHERE id=$1`, [id]);
  }
  return match;
}

module.exports = { sendOTP, verifyOTP };
