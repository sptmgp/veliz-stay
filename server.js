require('dotenv').config();
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const { v4: uuidv4 } = require('uuid');
const path     = require('path');
const { Pool } = require('pg');

const app    = express();
const SECRET = process.env.JWT_SECRET || 'veliz-dev-secret-change-in-prod';
const PORT   = process.env.PORT || 3000;

// ── Database ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ── Auto-migrate on startup ───────────────────────────────────────────────────
async function autoMigrate() {
  const client = await pool.connect();
  try {
    console.log('Running auto-migration...');
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role VARCHAR(20) NOT NULL DEFAULT 'guest',
        name VARCHAR(200) NOT NULL,
        email VARCHAR(200) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password_hash TEXT NOT NULL,
        phone_verified BOOLEAN DEFAULT false,
        email_verified BOOLEAN DEFAULT false,
        kyc_status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS properties (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id UUID NOT NULL REFERENCES users(id),
        status VARCHAR(20) DEFAULT 'pending',
        grade VARCHAR(10) DEFAULT 'Bronze',
        name VARCHAR(200) NOT NULL,
        type VARCHAR(50) NOT NULL,
        bhk INTEGER NOT NULL,
        town VARCHAR(100) NOT NULL,
        area VARCHAR(200) NOT NULL,
        address TEXT,
        distance_note VARCHAR(200),
        max_guests INTEGER NOT NULL DEFAULT 2,
        base_price INTEGER NOT NULL DEFAULT 400,
        parking_type VARCHAR(20) DEFAULT 'none',
        parking_vehicle VARCHAR(10) DEFAULT 'none',
        food_option VARCHAR(20) DEFAULT 'none',
        food_price INTEGER DEFAULT 0,
        description TEXT,
        house_rules TEXT,
        amenities TEXT[] DEFAULT '{}',
        photos TEXT[] DEFAULT '{}',
        rating NUMERIC(3,1) DEFAULT 0,
        review_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS otp_store (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        phone VARCHAR(20) NOT NULL,
        otp_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        verified BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        property_id UUID NOT NULL REFERENCES properties(id),
        guest_user_id UUID NOT NULL REFERENCES users(id),
        status VARCHAR(30) DEFAULT 'pending_owner',
        check_in DATE NOT NULL,
        check_out DATE NOT NULL,
        days INTEGER NOT NULL,
        guest_count INTEGER NOT NULL DEFAULT 1,
        purpose_of_visit VARCHAR(100),
        tariff_per_day INTEGER NOT NULL,
        total_amount INTEGER NOT NULL,
        breakdown JSONB DEFAULT '[]',
        parking_type VARCHAR(20) DEFAULT 'none',
        parking_vehicle VARCHAR(10) DEFAULT 'none',
        extra_services TEXT[] DEFAULT '{}',
        expires_at TIMESTAMPTZ,
        responded_at TIMESTAMPTZ,
        cancelled_at TIMESTAMPTZ,
        razorpay_order_id VARCHAR(100),
        razorpay_payment_id VARCHAR(100),
        payment_status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS guest_verifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        booking_id UUID NOT NULL REFERENCES bookings(id),
        guest_index INTEGER NOT NULL,
        full_name VARCHAR(200) NOT NULL,
        govt_id_type VARCHAR(50) NOT NULL,
        govt_id_number TEXT NOT NULL,
        phone VARCHAR(20) NOT NULL,
        email VARCHAR(200) NOT NULL,
        facebook_url TEXT,
        linkedin_url TEXT,
        phone_verified BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        property_id UUID NOT NULL REFERENCES properties(id),
        booking_id UUID REFERENCES bookings(id),
        guest_user_id UUID NOT NULL REFERENCES users(id),
        guest_name VARCHAR(200) NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT,
        owner_reply TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        booking_id UUID NOT NULL REFERENCES bookings(id),
        razorpay_order_id VARCHAR(100),
        razorpay_payment_id VARCHAR(100),
        amount INTEGER NOT NULL,
        currency VARCHAR(10) DEFAULT 'INR',
        status VARCHAR(20) DEFAULT 'created',
        owner_payout_amount INTEGER,
        owner_payout_status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        admin_id UUID REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        entity_type VARCHAR(50),
        entity_id UUID,
        details JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );`);

    // Seed admin
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@velizstay.com';
    const adminPass  = process.env.ADMIN_PASSWORD || 'VelizAdmin2026!';
    const existing   = await client.query('SELECT id FROM users WHERE email=$1', [adminEmail]);
    let adminId;
    if (!existing.rows.length) {
      const hash = bcrypt.hashSync(adminPass, 12);
      const r = await client.query(
        `INSERT INTO users (role,name,email,phone,password_hash,phone_verified,email_verified,kyc_status)
         VALUES ('admin','Veliz Admin',$1,'9999999999',$2,true,true,'verified') RETURNING id`,
        [adminEmail, hash]
      );
      adminId = r.rows[0].id;
      console.log('Admin user created:', adminEmail);
    } else {
      adminId = existing.rows[0].id;
      console.log('Admin already exists');
    }

    // Seed properties
    const propCount = await client.query('SELECT COUNT(*) FROM properties');
    if (parseInt(propCount.rows[0].count) === 0) {
      const seeds = [
        ['Nalini Coconut Home','House',2,'Pollachi','Aliyar Road','3.2 km from Pollachi town',4,650,'inside','car','daily_package',300,'Peaceful coconut farm homestead. Home-cooked meals, fresh coconut water daily. Perfect for families and nature lovers.','No smoking. Quiet after 10pm. ID verification mandatory.','{wifi,meals,car_parking,power_backup,ac}','Gold',4.9,34],
        ['Selvam Guest House','Apartment',1,'Coimbatore','Peelamedu','0.8 km from Tidel Park',2,480,'road','bike','none',0,'Clean well-connected apartment near Coimbatore IT corridor. Ideal for business travelers.','Working professionals preferred. No parties.','{wifi,bike_parking,laundry}','Silver',4.7,18],
        ['Valparai Mist Cabin','Cabin',2,'Coimbatore','Valparai','62 km from Pollachi',5,1100,'inside','car','free',0,'Eco-cabin in the misty Valparai hills. Free meals, wildlife corridor access, tea estate views.','Eco-stay. No plastic. Lights out by 11pm.','{wifi,free_meals,car_parking,security,wildlife_access}','Gold',4.9,52],
        ['Amaravathi Lakeside Stay','House',3,'Pollachi','Amaravathi','8 km from Pollachi town',6,820,'inside','car','pay_per_item',150,'Large 3BHK with stunning lake views. Perfect for group stays and family functions.','Groups welcome. Prior notice for functions. No loud music after 9pm.','{wifi,car_parking,power_backup,pay_per_meal}','Silver',4.8,27],
        ['Murugan Nivas Long Stay','House',2,'Udumalpet','Town Centre','0.4 km from bus stand',3,410,'road','bike','none',0,'Affordable central Udumalpet home. Monthly stays preferred. Quiet residential area.','Monthly stays preferred. Working adults only.','{wifi,bike_parking}','Bronze',4.6,11],
        ['Karpagam Farm Villa','Villa',3,'Pollachi','Topslip Road','5 km from Top Slip entrance',8,1200,'inside','car','free',0,'Premium villa on a working farm near Anaimalai Tiger Reserve. Free Kongu Nadu meals, guided forest walks.','Families and groups only. Min 2 night stay.','{wifi,free_meals,car_parking,security,power_backup,ac}','Gold',4.9,61]
      ];
      for (const s of seeds) {
        await client.query(
          `INSERT INTO properties (owner_id,name,type,bhk,town,area,distance_note,max_guests,base_price,
           parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities,grade,status,rating,review_count)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::text[],$17,'active',$18,$19)`,
          [adminId, ...s]
        );
      }
      console.log('6 sample properties seeded');
    } else {
      console.log('Properties already exist, skipping seed');
    }

    await client.query('COMMIT');
    console.log('Migration complete!');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Migration error:', err.message);
  } finally {
    client.release();
  }
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Tariff engine ─────────────────────────────────────────────────────────────
const SERVICE_RATES = { wifi:200, security:150, medical:100, laundry:120 };
function calcTariff(basePrice, parkingType, parkingVehicle, services=[]) {
  const base = Math.max(400, Math.min(1200, parseInt(basePrice)||400));
  let total = base;
  const breakdown = [{ label:'Base tariff (24h checkout)', amount:base }];
  if (parkingVehicle==='car' && parkingType==='inside') {
    const add=Math.round(base*0.25); total+=add;
    breakdown.push({ label:'Car parking — inside premises (+25%)', amount:add });
  } else if (parkingVehicle==='bike' && parkingType==='inside') {
    const add=Math.round(base*0.12); total+=add;
    breakdown.push({ label:'Two-wheeler parking — inside (+12%)', amount:add });
  } else if (parkingType==='road') {
    const add=Math.round(base*0.15); total+=add;
    breakdown.push({ label:`${parkingVehicle==='bike'?'Two-wheeler':'Car'} road parking (+15%)`, amount:add });
  }
  for (const svc of services) {
    if (SERVICE_RATES[svc]) { total+=SERVICE_RATES[svc]; breakdown.push({ label:`${svc} service`, amount:SERVICE_RATES[svc] }); }
  }
  return { base, total, breakdown };
}

// ── Middleware ────────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers.authorization||'').split(' ')[1];
  if (!token) return res.status(401).json({ error:'Authentication required' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error:'Invalid or expired token' }); }
}
function adminOnly(req,res,next) {
  if (req.user?.role!=='admin') return res.status(403).json({ error:'Admin only' });
  next();
}
function ownerOrAdmin(req,res,next) {
  if (!['owner','admin'].includes(req.user?.role)) return res.status(403).json({ error:'Owner or admin only' });
  next();
}
function asyncH(fn) { return (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next); }

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/auth/register', asyncH(async (req,res) => {
  const { name, email, password, role='guest', phone } = req.body;
  if (!name||!email||!password) return res.status(400).json({ error:'Name, email and password required' });
  if (!['guest','owner'].includes(role)) return res.status(400).json({ error:'Role must be guest or owner' });
  if (password.length<8) return res.status(400).json({ error:'Password must be at least 8 characters' });
  const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (exists.rows.length) return res.status(400).json({ error:'Email already registered' });
  const hash = bcrypt.hashSync(password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users (role,name,email,phone,password_hash) VALUES ($1,$2,$3,$4,$5) RETURNING id,role,name,email`,
    [role, name, email, phone||null, hash]
  );
  const user = rows[0];
  const token = jwt.sign({ id:user.id, role:user.role, name:user.name }, SECRET, { expiresIn:'7d' });
  res.status(201).json({ token, user });
}));

app.post('/api/auth/login', asyncH(async (req,res) => {
  const { email, password } = req.body;
  if (!email||!password) return res.status(400).json({ error:'Email and password required' });
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  if (!rows.length||!bcrypt.compareSync(password, rows[0].password_hash))
    return res.status(401).json({ error:'Invalid email or password' });
  const user = rows[0];
  const token = jwt.sign({ id:user.id, role:user.role, name:user.name }, SECRET, { expiresIn:'7d' });
  res.json({ token, user:{ id:user.id, role:user.role, name:user.name, email:user.email, phone:user.phone } });
}));

app.get('/api/auth/me', auth, asyncH(async (req,res) => {
  const { rows } = await pool.query(
    'SELECT id,role,name,email,phone,phone_verified,kyc_status,created_at FROM users WHERE id=$1', [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error:'User not found' });
  res.json(rows[0]);
}));

// ── Properties ────────────────────────────────────────────────────────────────
app.get('/api/properties', asyncH(async (req,res) => {
  const { town, minPrice, maxPrice, grade, amenities, search, sort } = req.query;
  let where = [`p.status = 'active'`]; let params = []; let i = 1;
  if (town)     { where.push(`p.town = $${i++}`); params.push(town); }
  if (minPrice) { where.push(`p.base_price >= $${i++}`); params.push(+minPrice); }
  if (maxPrice) { where.push(`p.base_price <= $${i++}`); params.push(+maxPrice); }
  if (grade)    { where.push(`p.grade = $${i++}`); params.push(grade); }
  if (amenities) { where.push(`p.amenities @> $${i++}::text[]`); params.push(`{${amenities.split(',').join(',')}}`); }
  if (search) { where.push(`(p.name ILIKE $${i} OR p.area ILIKE $${i} OR p.town ILIKE $${i})`); params.push(`%${search}%`); i++; }
  const orderMap = { rating:'p.rating DESC', price_asc:'p.base_price ASC', price_desc:'p.base_price DESC' };
  const order = orderMap[sort]||'p.created_at DESC';
  const { rows } = await pool.query(
    `SELECT p.*, u.name AS owner_name FROM properties p JOIN users u ON u.id=p.owner_id WHERE ${where.join(' AND ')} ORDER BY ${order}`,
    params
  );
  res.json({ total:rows.length, properties:rows });
}));

app.get('/api/properties/:id', asyncH(async (req,res) => {
  const { rows } = await pool.query(
    `SELECT p.*, u.name AS owner_name FROM properties p JOIN users u ON u.id=p.owner_id WHERE p.id=$1`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error:'Property not found' });
  const prop = rows[0];
  const reviews = await pool.query(
    `SELECT id,guest_name,rating,comment,created_at FROM reviews WHERE property_id=$1 ORDER BY created_at DESC LIMIT 20`,
    [prop.id]
  );
  const tariff = calcTariff(prop.base_price, prop.parking_type, prop.parking_vehicle);
  res.json({ ...prop, reviews:reviews.rows, tariff });
}));

app.post('/api/properties', auth, ownerOrAdmin, asyncH(async (req,res) => {
  const { name,type,bhk,town,area,address,distance_note,max_guests,base_price,
          parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities } = req.body;
  if (!name||!type||!town) return res.status(400).json({ error:'Name, type and town required' });
  const { rows } = await pool.query(
    `INSERT INTO properties (owner_id,name,type,bhk,town,area,address,distance_note,max_guests,base_price,
     parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
    [req.user.id,name,type,bhk||1,town,area||'',address||'',distance_note||'',
     max_guests||2,Math.max(400,Math.min(1200,base_price||400)),
     parking_type||'none',parking_vehicle||'none',food_option||'none',food_price||0,
     description||'',house_rules||'',amenities?`{${amenities.join(',')}}`:'{}'
    ]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/properties/:id', auth, asyncH(async (req,res) => {
  const { rows:[prop] } = await pool.query('SELECT * FROM properties WHERE id=$1', [req.params.id]);
  if (!prop) return res.status(404).json({ error:'Not found' });
  if (prop.owner_id!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error:'Not authorized' });
  const fields = ['name','type','bhk','town','area','address','distance_note','max_guests','base_price',
                  'parking_type','parking_vehicle','food_option','food_price','description','house_rules'];
  const updates=[]; const params=[]; let i=1;
  for (const f of fields) { if (req.body[f]!==undefined) { updates.push(`${f}=$${i++}`); params.push(req.body[f]); } }
  if (!updates.length) return res.status(400).json({ error:'Nothing to update' });
  updates.push(`updated_at=NOW()`); params.push(req.params.id);
  const { rows } = await pool.query(`UPDATE properties SET ${updates.join(',')} WHERE id=$${i} RETURNING *`, params);
  res.json(rows[0]);
}));

// ── Tariff ────────────────────────────────────────────────────────────────────
app.post('/api/tariff', (req,res) => {
  const { basePrice, parkingType, parkingVehicle, services } = req.body;
  res.json(calcTariff(basePrice, parkingType, parkingVehicle, services));
});

// ── OTP ───────────────────────────────────────────────────────────────────────
app.post('/api/verify/otp/send', asyncH(async (req,res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error:'Phone required' });
  const otp = Math.floor(100000+Math.random()*900000).toString();
  const hash = bcrypt.hashSync(otp, 8);
  const expires = new Date(Date.now()+10*60*1000);
  await pool.query(`INSERT INTO otp_store (phone,otp_hash,expires_at) VALUES ($1,$2,$3)`, [phone,hash,expires]);
  console.log(`OTP for ${phone}: ${otp}`);
  res.json({ message:'OTP sent', dev_otp: otp });
}));

app.post('/api/verify/otp/confirm', asyncH(async (req,res) => {
  const { phone, otp } = req.body;
  if (!phone||!otp) return res.status(400).json({ error:'Phone and OTP required' });
  const { rows } = await pool.query(
    `SELECT id,otp_hash FROM otp_store WHERE phone=$1 AND expires_at>NOW() AND verified=false ORDER BY created_at DESC LIMIT 1`,
    [phone]
  );
  if (!rows.length) return res.status(400).json({ error:'Invalid or expired OTP' });
  if (!bcrypt.compareSync(otp, rows[0].otp_hash)) return res.status(400).json({ error:'Wrong OTP' });
  await pool.query(`UPDATE otp_store SET verified=true WHERE id=$1`, [rows[0].id]);
  res.json({ verified:true });
}));

// ── Bookings ──────────────────────────────────────────────────────────────────
app.post('/api/bookings', auth, asyncH(async (req,res) => {
  const { property_id, check_in, check_out, guests=[], purpose_of_visit, parking_type, parking_vehicle, extra_services=[] } = req.body;
  if (!property_id||!check_in||!check_out) return res.status(400).json({ error:'Property and dates required' });
  if (!purpose_of_visit) return res.status(400).json({ error:'Purpose of visit required' });
  const guestCount = guests.length||1;
  if (guests.some(g=>!g.full_name||!g.govt_id_type||!g.govt_id_number||!g.phone||!g.email))
    return res.status(400).json({ error:'All guests must provide full ID details' });
  const { rows:[prop] } = await pool.query(`SELECT * FROM properties WHERE id=$1 AND status='active'`, [property_id]);
  if (!prop) return res.status(404).json({ error:'Property not found' });
  const days = Math.ceil((new Date(check_out)-new Date(check_in))/86400000);
  if (days<1) return res.status(400).json({ error:'Invalid dates' });
  const pType=parking_type||prop.parking_type, pVeh=parking_vehicle||prop.parking_vehicle;
  const tariff = calcTariff(prop.base_price, pType, pVeh, extra_services);
  const total = tariff.total*days;
  const expires = new Date(Date.now()+20*60*1000);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows:[booking] } = await client.query(
      `INSERT INTO bookings (property_id,guest_user_id,check_in,check_out,days,guest_count,purpose_of_visit,
       tariff_per_day,total_amount,breakdown,parking_type,parking_vehicle,extra_services,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [property_id,req.user.id,check_in,check_out,days,guestCount,purpose_of_visit,
       tariff.total,total,JSON.stringify(tariff.breakdown),pType,pVeh,`{${extra_services.join(',')}}`,expires]
    );
    for (let idx=0;idx<guests.length;idx++) {
      const g=guests[idx];
      await client.query(
        `INSERT INTO guest_verifications (booking_id,guest_index,full_name,govt_id_type,govt_id_number,phone,email,facebook_url,linkedin_url)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [booking.id,idx+1,g.full_name,g.govt_id_type,g.govt_id_number,g.phone,g.email,g.facebook_url||null,g.linkedin_url||null]
      );
    }
    await client.query('COMMIT');
    res.status(201).json({ ...booking, message:'Booking request sent. Owner has 20 minutes to respond.' });
  } catch(e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}));

app.get('/api/bookings', auth, asyncH(async (req,res) => {
  let query, params;
  if (req.user.role==='admin') {
    query=`SELECT b.*,p.name AS property_name,p.town,u.name AS guest_name FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id ORDER BY b.created_at DESC`;
    params=[];
  } else if (req.user.role==='owner') {
    query=`SELECT b.*,p.name AS property_name,p.town,u.name AS guest_name FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id WHERE p.owner_id=$1 ORDER BY b.created_at DESC`;
    params=[req.user.id];
  } else {
    query=`SELECT b.*,p.name AS property_name,p.town FROM bookings b JOIN properties p ON p.id=b.property_id WHERE b.guest_user_id=$1 ORDER BY b.created_at DESC`;
    params=[req.user.id];
  }
  const { rows } = await pool.query(query, params);
  res.json(rows);
}));

app.put('/api/bookings/:id/respond', auth, asyncH(async (req,res) => {
  const { action } = req.body;
  if (!['accept','decline'].includes(action)) return res.status(400).json({ error:'Action must be accept or decline' });
  const { rows:[b] } = await pool.query(
    'SELECT b.*,p.owner_id FROM bookings b JOIN properties p ON p.id=b.property_id WHERE b.id=$1', [req.params.id]
  );
  if (!b) return res.status(404).json({ error:'Booking not found' });
  if (b.owner_id!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error:'Not authorized' });
  if (b.status!=='pending_owner') return res.status(400).json({ error:'Booking already responded to' });
  if (new Date()>new Date(b.expires_at)) return res.status(400).json({ error:'20-minute window expired' });
  const { rows:[updated] } = await pool.query(
    `UPDATE bookings SET status=$1,responded_at=NOW(),updated_at=NOW() WHERE id=$2 RETURNING *`,
    [action==='accept'?'confirmed':'declined', req.params.id]
  );
  res.json(updated);
}));

app.put('/api/bookings/:id/cancel', auth, asyncH(async (req,res) => {
  const { rows:[b] } = await pool.query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
  if (!b) return res.status(404).json({ error:'Not found' });
  if (b.guest_user_id!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error:'Not authorized' });
  const { rows:[updated] } = await pool.query(
    `UPDATE bookings SET status='cancelled',cancelled_at=NOW(),updated_at=NOW() WHERE id=$1 RETURNING *`, [req.params.id]
  );
  res.json(updated);
}));

// ── Reviews ───────────────────────────────────────────────────────────────────
app.post('/api/reviews', auth, asyncH(async (req,res) => {
  const { property_id, rating, comment, booking_id } = req.body;
  if (!property_id||!rating) return res.status(400).json({ error:'Property and rating required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows:[review] } = await client.query(
      `INSERT INTO reviews (property_id,booking_id,guest_user_id,guest_name,rating,comment) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [property_id,booking_id||null,req.user.id,req.user.name,rating,comment||null]
    );
    await client.query(
      `UPDATE properties SET rating=(SELECT ROUND(AVG(rating)::numeric,1) FROM reviews WHERE property_id=$1),
       review_count=(SELECT COUNT(*) FROM reviews WHERE property_id=$1),updated_at=NOW() WHERE id=$1`, [property_id]
    );
    await client.query('COMMIT');
    res.status(201).json(review);
  } catch(e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}));

// ── Payments ──────────────────────────────────────────────────────────────────
app.post('/api/payments/create-order', auth, asyncH(async (req,res) => {
  const { booking_id } = req.body;
  const { rows:[b] } = await pool.query('SELECT * FROM bookings WHERE id=$1 AND guest_user_id=$2', [booking_id,req.user.id]);
  if (!b) return res.status(404).json({ error:'Booking not found' });
  const mockOrder = { id:`order_dev_${Date.now()}`, amount:b.total_amount*100, currency:'INR', status:'created' };
  res.json({ order:mockOrder, key_id:'rzp_dev_mode' });
}));

app.post('/api/payments/confirm', auth, asyncH(async (req,res) => {
  const { razorpay_order_id } = req.body;
  const { rows:[b] } = await pool.query(
    `UPDATE bookings SET payment_status='paid',status='confirmed',updated_at=NOW() WHERE razorpay_order_id=$1 OR id=$1 RETURNING *`,
    [razorpay_order_id]
  );
  res.json({ success:true, booking:b });
}));

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', auth, adminOnly, asyncH(async (req,res) => {
  const [props,bookings,users,revenue,towns] = await Promise.all([
    pool.query(`SELECT COUNT(*) total,COUNT(*) FILTER(WHERE status='active') active,COUNT(*) FILTER(WHERE status='pending') pending FROM properties`),
    pool.query(`SELECT COUNT(*) total,COUNT(*) FILTER(WHERE status='confirmed') confirmed,COUNT(*) FILTER(WHERE status='pending_owner') pending_owner FROM bookings`),
    pool.query(`SELECT COUNT(*) total,COUNT(*) FILTER(WHERE role='owner') owners,COUNT(*) FILTER(WHERE role='guest') guests FROM users`),
    pool.query(`SELECT COALESCE(SUM(total_amount),0) total FROM bookings WHERE payment_status='paid'`),
    pool.query(`SELECT town,COUNT(*) count FROM properties WHERE status='active' GROUP BY town ORDER BY count DESC`),
  ]);
  res.json({ properties:props.rows[0], bookings:bookings.rows[0], users:users.rows[0], totalRevenue:parseInt(revenue.rows[0].total), townBreakdown:towns.rows });
}));

app.get('/api/admin/bookings', auth, adminOnly, asyncH(async (req,res) => {
  const { rows } = await pool.query(
    `SELECT b.*,p.name AS property_name,p.town,u.name AS guest_name,u.email AS guest_email
     FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id
     ORDER BY b.created_at DESC LIMIT 200`
  );
  res.json(rows);
}));

app.get('/api/admin/pending-bookings', auth, adminOnly, asyncH(async (req,res) => {
  const { rows } = await pool.query(
    `SELECT b.*,p.name AS property_name,p.town,p.owner_id,u.name AS guest_name,ow.name AS owner_name
     FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id JOIN users ow ON ow.id=p.owner_id
     WHERE b.status='pending_owner' AND b.expires_at>NOW() ORDER BY b.expires_at ASC`
  );
  res.json(rows);
}));

app.put('/api/admin/properties/:id', auth, adminOnly, asyncH(async (req,res) => {
  const { grade, status } = req.body;
  const updates=[]; const params=[]; let i=1;
  if (grade)  { updates.push(`grade=$${i++}`);  params.push(grade); }
  if (status) { updates.push(`status=$${i++}`); params.push(status); }
  if (!updates.length) return res.status(400).json({ error:'Nothing to update' });
  updates.push(`updated_at=NOW()`); params.push(req.params.id);
  const { rows } = await pool.query(`UPDATE properties SET ${updates.join(',')} WHERE id=$${i} RETURNING *`, params);
  if (!rows.length) return res.status(404).json({ error:'Not found' });
  res.json(rows[0]);
}));

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', asyncH(async (req,res) => {
  try { await pool.query('SELECT 1'); res.json({ status:'ok', db:'connected', env:process.env.NODE_ENV, ts:new Date().toISOString() }); }
  catch { res.status(503).json({ status:'error', db:'disconnected' }); }
}));

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err,req,res,_next) => {
  console.error(err.message);
  res.status(500).json({ error: process.env.NODE_ENV==='production' ? 'Internal server error' : err.message });
});

// ── Serve SPA ─────────────────────────────────────────────────────────────────
app.get('/{*splat}', (req,res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  if (process.env.DATABASE_URL) {
    await autoMigrate();
  } else {
    console.log('No DATABASE_URL — skipping migration');
  }
  app.listen(PORT, () => {
    console.log(`\n🏡 Veliz Stay running → http://localhost:${PORT}`);
    console.log(`   ENV: ${process.env.NODE_ENV||'development'}`);
    console.log(`   DB:  ${process.env.DATABASE_URL?'PostgreSQL connected':'Not configured'}\n`);
  });
}

start();
