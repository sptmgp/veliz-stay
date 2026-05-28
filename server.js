require('dotenv').config();
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const { v4: uuidv4 } = require('uuid');
const path     = require('path');
const pool     = require('./src/db');
const { calcTariff } = require('./src/tariff');
const { sendOTP, verifyOTP } = require('./src/otp');
const { createOrder, confirmPayment } = require('./src/payments');

const app    = express();
const SECRET = process.env.JWT_SECRET || 'veliz-dev-secret-change-in-prod';
const PORT   = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Middleware ────────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function ownerOrAdmin(req, res, next) {
  if (!['owner','admin'].includes(req.user?.role)) return res.status(403).json({ error: 'Owner or admin access required' });
  next();
}

function asyncH(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', asyncH(async (req, res) => {
  const { name, email, password, role = 'guest', phone } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
  if (!['guest','owner'].includes(role)) return res.status(400).json({ error: 'Role must be guest or owner' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (exists.rows.length) return res.status(400).json({ error: 'Email already registered' });

  const hash = bcrypt.hashSync(password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users (role,name,email,phone,password_hash) VALUES ($1,$2,$3,$4,$5) RETURNING id,role,name,email`,
    [role, name, email, phone || null, hash]
  );
  const user = rows[0];
  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user });
}));

app.post('/api/auth/login', asyncH(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  if (!rows.length || !bcrypt.compareSync(password, rows[0].password_hash))
    return res.status(401).json({ error: 'Invalid email or password' });
  const user = rows[0];
  const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, role: user.role, name: user.name, email: user.email, phone: user.phone } });
}));

app.get('/api/auth/me', auth, asyncH(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,role,name,email,phone,phone_verified,kyc_status,created_at FROM users WHERE id=$1',
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  res.json(rows[0]);
}));

// ── Properties ────────────────────────────────────────────────────────────────
app.get('/api/properties', asyncH(async (req, res) => {
  const { town, minPrice, maxPrice, grade, amenities, search, sort } = req.query;
  let where = [`p.status = 'active'`];
  let params = [];
  let i = 1;

  if (town)     { where.push(`p.town = $${i++}`); params.push(town); }
  if (minPrice) { where.push(`p.base_price >= $${i++}`); params.push(+minPrice); }
  if (maxPrice) { where.push(`p.base_price <= $${i++}`); params.push(+maxPrice); }
  if (grade)    { where.push(`p.grade = $${i++}`); params.push(grade); }
  if (amenities) {
    const list = amenities.split(',');
    where.push(`p.amenities @> $${i++}::text[]`);
    params.push(`{${list.join(',')}}`);
  }
  if (search) {
    where.push(`(p.name ILIKE $${i} OR p.area ILIKE $${i} OR p.town ILIKE $${i})`);
    params.push(`%${search}%`); i++;
  }

  const orderMap = {
    rating:     'p.rating DESC, p.review_count DESC',
    price_asc:  'p.base_price ASC',
    price_desc: 'p.base_price DESC',
  };
  const order = orderMap[sort] || 'p.created_at DESC';

  const { rows } = await pool.query(
    `SELECT p.*, u.name AS owner_name FROM properties p
     JOIN users u ON u.id = p.owner_id
     WHERE ${where.join(' AND ')} ORDER BY ${order}`,
    params
  );
  res.json({ total: rows.length, properties: rows });
}));

app.get('/api/properties/:id', asyncH(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT p.*, u.name AS owner_name FROM properties p
     JOIN users u ON u.id = p.owner_id WHERE p.id=$1`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Property not found' });
  const prop = rows[0];
  const reviews = await pool.query(
    `SELECT id,guest_name,rating,comment,created_at FROM reviews
     WHERE property_id=$1 ORDER BY created_at DESC LIMIT 20`,
    [prop.id]
  );
  const tariff = calcTariff(prop.base_price, prop.parking_type, prop.parking_vehicle);
  res.json({ ...prop, reviews: reviews.rows, tariff });
}));

app.post('/api/properties', auth, ownerOrAdmin, asyncH(async (req, res) => {
  const {
    name, type, bhk, town, area, address, distance_note, max_guests, base_price,
    parking_type, parking_vehicle, food_option, food_price, description, house_rules, amenities
  } = req.body;
  if (!name || !type || !town) return res.status(400).json({ error: 'Name, type and town required' });

  const { rows } = await pool.query(
    `INSERT INTO properties
     (owner_id,name,type,bhk,town,area,address,distance_note,max_guests,base_price,
      parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
    [req.user.id, name, type, bhk||1, town, area||'', address||'', distance_note||'',
     max_guests||2, Math.max(400,Math.min(1200,base_price||400)),
     parking_type||'none', parking_vehicle||'none',
     food_option||'none', food_price||0,
     description||'', house_rules||'',
     amenities ? `{${amenities.join(',')}}` : '{}']
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/properties/:id', auth, asyncH(async (req, res) => {
  const { rows: [prop] } = await pool.query('SELECT * FROM properties WHERE id=$1', [req.params.id]);
  if (!prop) return res.status(404).json({ error: 'Property not found' });
  if (prop.owner_id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Not authorized' });

  const fields = ['name','type','bhk','town','area','address','distance_note','max_guests',
                  'base_price','parking_type','parking_vehicle','food_option','food_price',
                  'description','house_rules'];
  const updates = []; const params = [];
  let i = 1;
  for (const f of fields) {
    if (req.body[f] !== undefined) { updates.push(`${f}=$${i++}`); params.push(req.body[f]); }
  }
  if (!updates.length) return res.status(400).json({ error: 'No fields to update' });
  updates.push(`updated_at=NOW()`);
  params.push(req.params.id);
  const { rows } = await pool.query(
    `UPDATE properties SET ${updates.join(',')} WHERE id=$${i} RETURNING *`, params
  );
  res.json(rows[0]);
}));

// ── Tariff calculator ──────────────────────────────────────────────────────────
app.post('/api/tariff', (req, res) => {
  const { basePrice, parkingType, parkingVehicle, services } = req.body;
  res.json(calcTariff(basePrice, parkingType, parkingVehicle, services));
});

// ── OTP ────────────────────────────────────────────────────────────────────────
app.post('/api/verify/otp/send', asyncH(async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number required' });
  const result = await sendOTP(phone);
  res.json({ message: 'OTP sent', ...(result.dev_otp ? { dev_otp: result.dev_otp } : {}) });
}));

app.post('/api/verify/otp/confirm', asyncH(async (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP required' });
  const ok = await verifyOTP(phone, otp);
  if (!ok) return res.status(400).json({ error: 'Invalid or expired OTP' });
  res.json({ verified: true });
}));

// ── Bookings ──────────────────────────────────────────────────────────────────
app.post('/api/bookings', auth, asyncH(async (req, res) => {
  const {
    property_id, check_in, check_out, guests = [],
    purpose_of_visit, parking_type, parking_vehicle, extra_services = []
  } = req.body;

  if (!property_id || !check_in || !check_out) return res.status(400).json({ error: 'Property and dates required' });
  if (!purpose_of_visit) return res.status(400).json({ error: 'Purpose of visit required' });

  const guestCount = guests.length || 1;

  // ── Guest evidence validation ──────────────────────────────────────────────
  if (guestCount >= 1 && guests.some(g => !g.full_name || !g.govt_id_type || !g.govt_id_number || !g.phone || !g.email))
    return res.status(400).json({ error: 'All guests must provide full name, government ID, phone and email' });
  if (guestCount === 2 && guests.filter(g => g.govt_id_number && g.phone).length < 2)
    return res.status(400).json({ error: 'Both guests must provide evidence' });
  if (guestCount >= 3 && guests.length < guestCount)
    return res.status(400).json({ error: 'All guests must provide complete details for groups of 3 or more' });

  const { rows: [prop] } = await pool.query('SELECT * FROM properties WHERE id=$1 AND status=$2', [property_id, 'active']);
  if (!prop) return res.status(404).json({ error: 'Property not found or unavailable' });

  const ci = new Date(check_in), co = new Date(check_out);
  if (co <= ci) return res.status(400).json({ error: 'Check-out must be after check-in' });
  const days = Math.ceil((co - ci) / 86400000);
  if (days < 1) return res.status(400).json({ error: 'Minimum 1 day stay' });

  const pType  = parking_type   || prop.parking_type;
  const pVeh   = parking_vehicle || prop.parking_vehicle;
  const tariff = calcTariff(prop.base_price, pType, pVeh, extra_services);
  const total  = tariff.total * days;
  const expires = new Date(Date.now() + 20 * 60 * 1000); // 20 min owner window

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [booking] } = await client.query(
      `INSERT INTO bookings
       (property_id,guest_user_id,check_in,check_out,days,guest_count,purpose_of_visit,
        tariff_per_day,total_amount,breakdown,parking_type,parking_vehicle,extra_services,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [property_id, req.user.id, check_in, check_out, days, guestCount, purpose_of_visit,
       tariff.total, total, JSON.stringify(tariff.breakdown),
       pType, pVeh, `{${extra_services.join(',')}}`, expires]
    );

    // Store guest verification details (encrypted at rest by Supabase)
    for (let idx = 0; idx < guests.length; idx++) {
      const g = guests[idx];
      await client.query(
        `INSERT INTO guest_verifications
         (booking_id,guest_index,full_name,govt_id_type,govt_id_number,phone,email,facebook_url,linkedin_url)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [booking.id, idx+1, g.full_name, g.govt_id_type, g.govt_id_number,
         g.phone, g.email, g.facebook_url||null, g.linkedin_url||null]
      );
    }

    await client.query('COMMIT');
    res.status(201).json({ ...booking, message: 'Booking request sent. Owner has 20 minutes to respond.' });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

app.get('/api/bookings', auth, asyncH(async (req, res) => {
  let query, params;
  if (req.user.role === 'admin') {
    query = `SELECT b.*, p.name AS property_name, p.town, u.name AS guest_name
             FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id
             ORDER BY b.created_at DESC`;
    params = [];
  } else if (req.user.role === 'owner') {
    query = `SELECT b.*, p.name AS property_name, p.town, u.name AS guest_name
             FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id
             WHERE p.owner_id=$1 ORDER BY b.created_at DESC`;
    params = [req.user.id];
  } else {
    query = `SELECT b.*, p.name AS property_name, p.town
             FROM bookings b JOIN properties p ON p.id=b.property_id
             WHERE b.guest_user_id=$1 ORDER BY b.created_at DESC`;
    params = [req.user.id];
  }
  const { rows } = await pool.query(query, params);
  res.json(rows);
}));

app.get('/api/bookings/:id', auth, asyncH(async (req, res) => {
  const { rows: [b] } = await pool.query(
    `SELECT b.*, p.name AS property_name, p.town, p.owner_id,
            u.name AS guest_name, u.email AS guest_email
     FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id
     WHERE b.id=$1`,
    [req.params.id]
  );
  if (!b) return res.status(404).json({ error: 'Booking not found' });
  if (b.guest_user_id !== req.user.id && b.owner_id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Not authorized' });

  // Admin & owner can see guest verifications
  let guestDetails = [];
  if (req.user.role === 'admin') {
    const gv = await pool.query(
      'SELECT * FROM guest_verifications WHERE booking_id=$1 ORDER BY guest_index',
      [b.id]
    );
    guestDetails = gv.rows;
  } else if (b.owner_id === req.user.id) {
    // Owner sees only lead guest first name + verified count (not full details)
    const gv = await pool.query(
      `SELECT guest_index,
              LEFT(full_name, POSITION(' ' IN full_name || ' ') - 1) AS first_name,
              true AS verified
       FROM guest_verifications WHERE booking_id=$1 ORDER BY guest_index`,
      [b.id]
    );
    guestDetails = gv.rows;
  }

  res.json({ ...b, guest_details: guestDetails });
}));

app.put('/api/bookings/:id/respond', auth, asyncH(async (req, res) => {
  const { action } = req.body;
  if (!['accept','decline'].includes(action)) return res.status(400).json({ error: 'Action must be accept or decline' });

  const { rows: [b] } = await pool.query(
    'SELECT b.*, p.owner_id FROM bookings b JOIN properties p ON p.id=b.property_id WHERE b.id=$1',
    [req.params.id]
  );
  if (!b) return res.status(404).json({ error: 'Booking not found' });
  if (b.owner_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not authorized' });
  if (b.status !== 'pending_owner') return res.status(400).json({ error: 'Booking is no longer pending' });
  if (new Date() > new Date(b.expires_at)) return res.status(400).json({ error: '20-minute response window has expired' });

  const newStatus = action === 'accept' ? 'confirmed' : 'declined';
  const { rows: [updated] } = await pool.query(
    `UPDATE bookings SET status=$1, responded_at=NOW(), updated_at=NOW() WHERE id=$2 RETURNING *`,
    [newStatus, req.params.id]
  );
  res.json(updated);
}));

app.put('/api/bookings/:id/cancel', auth, asyncH(async (req, res) => {
  const { rows: [b] } = await pool.query(
    'SELECT b.*, p.owner_id FROM bookings b JOIN properties p ON p.id=b.property_id WHERE b.id=$1',
    [req.params.id]
  );
  if (!b) return res.status(404).json({ error: 'Booking not found' });
  if (b.guest_user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not authorized' });
  if (['cancelled','completed','declined'].includes(b.status)) return res.status(400).json({ error: 'Cannot cancel this booking' });

  const { rows: [updated] } = await pool.query(
    `UPDATE bookings SET status='cancelled', cancelled_at=NOW(), updated_at=NOW() WHERE id=$1 RETURNING *`,
    [req.params.id]
  );
  res.json(updated);
}));

// ── Payments ──────────────────────────────────────────────────────────────────
app.post('/api/payments/create-order', auth, asyncH(async (req, res) => {
  const { booking_id } = req.body;
  const { rows: [b] } = await pool.query('SELECT * FROM bookings WHERE id=$1 AND guest_user_id=$2', [booking_id, req.user.id]);
  if (!b) return res.status(404).json({ error: 'Booking not found' });
  if (b.status !== 'confirmed') return res.status(400).json({ error: 'Booking must be confirmed before payment' });
  const order = await createOrder(booking_id, b.total_amount);
  res.json({ order, key_id: process.env.RAZORPAY_KEY_ID || 'rzp_dev_mode' });
}));

app.post('/api/payments/confirm', auth, asyncH(async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  if (!razorpay_order_id || !razorpay_payment_id) return res.status(400).json({ error: 'Payment details required' });
  const booking = await confirmPayment(razorpay_order_id, razorpay_payment_id, razorpay_signature || '');
  res.json({ success: true, booking });
}));

// ── Reviews ───────────────────────────────────────────────────────────────────
app.post('/api/reviews', auth, asyncH(async (req, res) => {
  const { property_id, rating, comment, booking_id } = req.body;
  if (!property_id || !rating) return res.status(400).json({ error: 'Property and rating required' });
  if (rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1–5' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [review] } = await client.query(
      `INSERT INTO reviews (property_id,booking_id,guest_user_id,guest_name,rating,comment)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [property_id, booking_id||null, req.user.id, req.user.name, rating, comment||null]
    );
    await client.query(
      `UPDATE properties SET
         rating=(SELECT ROUND(AVG(rating)::numeric,1) FROM reviews WHERE property_id=$1),
         review_count=(SELECT COUNT(*) FROM reviews WHERE property_id=$1),
         updated_at=NOW()
       WHERE id=$1`,
      [property_id]
    );
    await client.query('COMMIT');
    res.status(201).json(review);
  } catch (e) {
    await client.query('ROLLBACK'); throw e;
  } finally {
    client.release();
  }
}));

app.get('/api/reviews/:propertyId', asyncH(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,guest_name,rating,comment,owner_reply,created_at FROM reviews
     WHERE property_id=$1 ORDER BY created_at DESC`,
    [req.params.propertyId]
  );
  res.json(rows);
}));

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', auth, adminOnly, asyncH(async (req, res) => {
  const [props, bookings, users, revenue, towns] = await Promise.all([
    pool.query(`SELECT COUNT(*) total, COUNT(*) FILTER(WHERE status='active') active, COUNT(*) FILTER(WHERE status='pending') pending FROM properties`),
    pool.query(`SELECT COUNT(*) total, COUNT(*) FILTER(WHERE status='confirmed') confirmed, COUNT(*) FILTER(WHERE status='pending_owner') pending_owner FROM bookings`),
    pool.query(`SELECT COUNT(*) total, COUNT(*) FILTER(WHERE role='owner') owners, COUNT(*) FILTER(WHERE role='guest') guests FROM users`),
    pool.query(`SELECT COALESCE(SUM(total_amount),0) total FROM bookings WHERE payment_status='paid'`),
    pool.query(`SELECT town, COUNT(*) count FROM properties WHERE status='active' GROUP BY town ORDER BY count DESC`),
  ]);
  res.json({
    properties: props.rows[0],
    bookings: bookings.rows[0],
    users: users.rows[0],
    totalRevenue: parseInt(revenue.rows[0].total),
    townBreakdown: towns.rows,
  });
}));

app.get('/api/admin/users', auth, adminOnly, asyncH(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,role,name,email,phone,phone_verified,kyc_status,created_at FROM users ORDER BY created_at DESC'
  );
  res.json(rows);
}));

app.put('/api/admin/properties/:id', auth, adminOnly, asyncH(async (req, res) => {
  const { grade, status } = req.body;
  const updates = []; const params = []; let i = 1;
  if (grade)  { updates.push(`grade=$${i++}`);  params.push(grade); }
  if (status) { updates.push(`status=$${i++}`); params.push(status); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  updates.push(`updated_at=NOW()`);
  params.push(req.params.id);
  const { rows } = await pool.query(
    `UPDATE properties SET ${updates.join(',')} WHERE id=$${i} RETURNING *`, params
  );
  if (!rows.length) return res.status(404).json({ error: 'Property not found' });
  await pool.query(
    `INSERT INTO audit_log (admin_id,action,entity_type,entity_id,details) VALUES ($1,$2,'property',$3,$4)`,
    [req.user.id, `Updated property: ${updates.join(', ')}`, req.params.id, JSON.stringify(req.body)]
  );
  res.json(rows[0]);
}));

app.get('/api/admin/bookings', auth, adminOnly, asyncH(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.*, p.name AS property_name, p.town, u.name AS guest_name, u.email AS guest_email
     FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id
     ORDER BY b.created_at DESC LIMIT 200`
  );
  res.json(rows);
}));

app.get('/api/admin/pending-bookings', auth, adminOnly, asyncH(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.*, p.name AS property_name, p.town, p.owner_id,
            u.name AS guest_name, ow.name AS owner_name
     FROM bookings b
     JOIN properties p ON p.id=b.property_id
     JOIN users u ON u.id=b.guest_user_id
     JOIN users ow ON ow.id=p.owner_id
     WHERE b.status='pending_owner' AND b.expires_at > NOW()
     ORDER BY b.expires_at ASC`
  );
  res.json(rows);
}));

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', asyncH(async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', env: process.env.NODE_ENV, ts: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
}));

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err.stack);
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ── Serve SPA ─────────────────────────────────────────────────────────────────
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🏡 Veliz Stay running → http://localhost:${PORT}`);
  console.log(`   ENV: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   DB:  ${process.env.DATABASE_URL ? 'PostgreSQL configured' : 'Not configured — set DATABASE_URL'}\n`);
});

module.exports = app;
