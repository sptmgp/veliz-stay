require('dotenv').config();
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');
const { Pool } = require('pg');

const app    = express();
const SECRET = process.env.JWT_SECRET || 'veliz-dev-secret';
const PORT   = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── DB Pool ───────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

// ── Tariff ────────────────────────────────────────────────────────────────────
const SVC = { wifi:200, security:150, medical:100, laundry:120 };
function calcTariff(base, pt, pv, svcs=[]) {
  base = Math.max(400, Math.min(1200, parseInt(base)||400));
  let total = base;
  const bd = [{ label:'Base tariff (24h)', amount:base }];
  if (pv==='car'&&pt==='inside')  { const a=Math.round(base*.25); total+=a; bd.push({ label:'Car parking inside (+25%)', amount:a }); }
  else if (pv==='bike'&&pt==='inside') { const a=Math.round(base*.12); total+=a; bd.push({ label:'Bike parking inside (+12%)', amount:a }); }
  else if (pt==='road') { const a=Math.round(base*.15); total+=a; bd.push({ label:'Road parking (+15%)', amount:a }); }
  for (const s of svcs) if (SVC[s]) { total+=SVC[s]; bd.push({ label:s+' service', amount:SVC[s] }); }
  return { base, total, breakdown:bd };
}

// ── Middleware ────────────────────────────────────────────────────────────────
function auth(req,res,next) {
  const t=(req.headers.authorization||'').split(' ')[1];
  if (!t) return res.status(401).json({ error:'Auth required' });
  try { req.user=jwt.verify(t,SECRET); next(); }
  catch { res.status(401).json({ error:'Invalid token' }); }
}
const adminOnly=(req,res,next)=>req.user?.role==='admin'?next():res.status(403).json({ error:'Admin only' });
const ownerOrAdmin=(req,res,next)=>['owner','admin'].includes(req.user?.role)?next():res.status(403).json({ error:'Owner/admin only' });
const H=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', H(async(req,res)=>{
  try { await pool.query('SELECT 1'); res.json({ status:'ok', db:'connected' }); }
  catch(e) { res.json({ status:'degraded', db:'connecting', error:e.message }); }
}));

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', H(async(req,res)=>{
  const { name,email,password,role='guest',phone }=req.body;
  if (!name||!email||!password) return res.status(400).json({ error:'Name, email, password required' });
  if (password.length<8) return res.status(400).json({ error:'Password min 8 chars' });
  if (!['guest','owner'].includes(role)) return res.status(400).json({ error:'Invalid role' });
  const ex=await pool.query('SELECT id FROM users WHERE email=$1',[email]);
  if (ex.rows.length) return res.status(400).json({ error:'Email already registered' });
  const hash=bcrypt.hashSync(password,12);
  const { rows }=await pool.query(
    `INSERT INTO users (role,name,email,phone,password_hash) VALUES ($1,$2,$3,$4,$5) RETURNING id,role,name,email`,
    [role,name,email,phone||null,hash]
  );
  const token=jwt.sign({ id:rows[0].id,role:rows[0].role,name:rows[0].name },SECRET,{ expiresIn:'7d' });
  res.status(201).json({ token, user:rows[0] });
}));

app.post('/api/auth/login', H(async(req,res)=>{
  const { email,password }=req.body;
  const { rows }=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
  if (!rows.length||!bcrypt.compareSync(password,rows[0].password_hash))
    return res.status(401).json({ error:'Invalid email or password' });
  const u=rows[0];
  const token=jwt.sign({ id:u.id,role:u.role,name:u.name },SECRET,{ expiresIn:'7d' });
  res.json({ token, user:{ id:u.id,role:u.role,name:u.name,email:u.email,phone:u.phone } });
}));

app.get('/api/auth/me', auth, H(async(req,res)=>{
  const { rows }=await pool.query('SELECT id,role,name,email,phone,created_at FROM users WHERE id=$1',[req.user.id]);
  if (!rows.length) return res.status(404).json({ error:'Not found' });
  res.json(rows[0]);
}));

// ── Properties ────────────────────────────────────────────────────────────────
app.get('/api/properties', H(async(req,res)=>{
  const { town,minPrice,maxPrice,grade,search,sort }=req.query;
  let w=[`p.status='active'`],p=[],i=1;
  if (town)     { w.push(`p.town=$${i++}`); p.push(town); }
  if (minPrice) { w.push(`p.base_price>=$${i++}`); p.push(+minPrice); }
  if (maxPrice) { w.push(`p.base_price<=$${i++}`); p.push(+maxPrice); }
  if (grade)    { w.push(`p.grade=$${i++}`); p.push(grade); }
  if (search)   { w.push(`(p.name ILIKE $${i} OR p.area ILIKE $${i} OR p.town ILIKE $${i})`); p.push(`%${search}%`); i++; }
  const ord={ rating:'p.rating DESC',price_asc:'p.base_price ASC',price_desc:'p.base_price DESC' }[sort]||'p.created_at DESC';
  const { rows }=await pool.query(`SELECT p.*,u.name owner_name FROM properties p JOIN users u ON u.id=p.owner_id WHERE ${w.join(' AND ')} ORDER BY ${ord}`,p);
  res.json({ total:rows.length, properties:rows });
}));

app.get('/api/properties/:id', H(async(req,res)=>{
  const { rows }=await pool.query(`SELECT p.*,u.name owner_name FROM properties p JOIN users u ON u.id=p.owner_id WHERE p.id=$1`,[req.params.id]);
  if (!rows.length) return res.status(404).json({ error:'Not found' });
  const prop=rows[0];
  const rev=await pool.query(`SELECT id,guest_name,rating,comment,created_at FROM reviews WHERE property_id=$1 ORDER BY created_at DESC LIMIT 20`,[prop.id]);
  res.json({ ...prop, reviews:rev.rows, tariff:calcTariff(prop.base_price,prop.parking_type,prop.parking_vehicle) });
}));

app.post('/api/properties', auth, ownerOrAdmin, H(async(req,res)=>{
  const { name,type,bhk,town,area,address,distance_note,max_guests,base_price,parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities }=req.body;
  if (!name||!type||!town) return res.status(400).json({ error:'Name, type, town required' });
  const { rows }=await pool.query(
    `INSERT INTO properties (owner_id,name,type,bhk,town,area,address,distance_note,max_guests,base_price,parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
    [req.user.id,name,type,bhk||1,town,area||'',address||'',distance_note||'',max_guests||2,
     Math.max(400,Math.min(1200,base_price||400)),parking_type||'none',parking_vehicle||'none',
     food_option||'none',food_price||0,description||'',house_rules||'',
     amenities?`{${amenities.join(',')}}`:'{}'
    ]
  );
  res.status(201).json(rows[0]);
}));

// ── OTP ───────────────────────────────────────────────────────────────────────
app.post('/api/verify/otp/send', H(async(req,res)=>{
  const { phone }=req.body;
  if (!phone) return res.status(400).json({ error:'Phone required' });
  const otp=Math.floor(100000+Math.random()*900000).toString();
  const hash=bcrypt.hashSync(otp,8);
  await pool.query(`INSERT INTO otp_store (phone,otp_hash,expires_at) VALUES ($1,$2,$3)`,[phone,hash,new Date(Date.now()+600000)]);
  console.log(`OTP ${phone}: ${otp}`);
  res.json({ message:'OTP sent', dev_otp:otp });
}));

app.post('/api/verify/otp/confirm', H(async(req,res)=>{
  const { phone,otp }=req.body;
  const { rows }=await pool.query(`SELECT id,otp_hash FROM otp_store WHERE phone=$1 AND expires_at>NOW() AND verified=false ORDER BY created_at DESC LIMIT 1`,[phone]);
  if (!rows.length||!bcrypt.compareSync(otp,rows[0].otp_hash)) return res.status(400).json({ error:'Invalid OTP' });
  await pool.query(`UPDATE otp_store SET verified=true WHERE id=$1`,[rows[0].id]);
  res.json({ verified:true });
}));

// ── Bookings ──────────────────────────────────────────────────────────────────
app.post('/api/bookings', auth, H(async(req,res)=>{
  const { property_id,check_in,check_out,guests=[],purpose_of_visit,parking_type,parking_vehicle,extra_services=[] }=req.body;
  if (!property_id||!check_in||!check_out) return res.status(400).json({ error:'Property and dates required' });
  if (!purpose_of_visit) return res.status(400).json({ error:'Purpose of visit required' });
  if (guests.some(g=>!g.full_name||!g.govt_id_type||!g.govt_id_number||!g.phone||!g.email))
    return res.status(400).json({ error:'All guests must provide full ID details' });
  const { rows:[prop] }=await pool.query(`SELECT * FROM properties WHERE id=$1 AND status='active'`,[property_id]);
  if (!prop) return res.status(404).json({ error:'Property not found' });
  const days=Math.ceil((new Date(check_out)-new Date(check_in))/86400000);
  if (days<1) return res.status(400).json({ error:'Invalid dates' });
  const t=calcTariff(prop.base_price,parking_type||prop.parking_type,parking_vehicle||prop.parking_vehicle,extra_services);
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows:[b] }=await client.query(
      `INSERT INTO bookings (property_id,guest_user_id,check_in,check_out,days,guest_count,purpose_of_visit,tariff_per_day,total_amount,breakdown,parking_type,parking_vehicle,extra_services,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [property_id,req.user.id,check_in,check_out,days,guests.length||1,purpose_of_visit,t.total,t.total*days,
       JSON.stringify(t.breakdown),parking_type||prop.parking_type,parking_vehicle||prop.parking_vehicle,
       `{${extra_services.join(',')}}`,new Date(Date.now()+1200000)]
    );
    for (let i=0;i<guests.length;i++) {
      const g=guests[i];
      await client.query(
        `INSERT INTO guest_verifications (booking_id,guest_index,full_name,govt_id_type,govt_id_number,phone,email,facebook_url,linkedin_url) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [b.id,i+1,g.full_name,g.govt_id_type,g.govt_id_number,g.phone,g.email,g.facebook_url||null,g.linkedin_url||null]
      );
    }
    await client.query('COMMIT');
    res.status(201).json({ ...b, message:'Booking sent. Owner has 20 minutes to respond.' });
  } catch(e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}));

app.get('/api/bookings', auth, H(async(req,res)=>{
  let q,p;
  if (req.user.role==='admin') { q=`SELECT b.*,p.name property_name,p.town,u.name guest_name FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id ORDER BY b.created_at DESC`; p=[]; }
  else if (req.user.role==='owner') { q=`SELECT b.*,p.name property_name,p.town,u.name guest_name FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id WHERE p.owner_id=$1 ORDER BY b.created_at DESC`; p=[req.user.id]; }
  else { q=`SELECT b.*,p.name property_name,p.town FROM bookings b JOIN properties p ON p.id=b.property_id WHERE b.guest_user_id=$1 ORDER BY b.created_at DESC`; p=[req.user.id]; }
  const { rows }=await pool.query(q,p);
  res.json(rows);
}));

app.put('/api/bookings/:id/respond', auth, H(async(req,res)=>{
  const { action }=req.body;
  if (!['accept','decline'].includes(action)) return res.status(400).json({ error:'Invalid action' });
  const { rows:[b] }=await pool.query(`SELECT b.*,p.owner_id FROM bookings b JOIN properties p ON p.id=b.property_id WHERE b.id=$1`,[req.params.id]);
  if (!b) return res.status(404).json({ error:'Not found' });
  if (b.owner_id!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error:'Not authorized' });
  if (b.status!=='pending_owner') return res.status(400).json({ error:'Already responded' });
  if (new Date()>new Date(b.expires_at)) return res.status(400).json({ error:'20-min window expired' });
  const { rows:[u] }=await pool.query(`UPDATE bookings SET status=$1,responded_at=NOW() WHERE id=$2 RETURNING *`,[action==='accept'?'confirmed':'declined',req.params.id]);
  res.json(u);
}));

app.put('/api/bookings/:id/cancel', auth, H(async(req,res)=>{
  const { rows:[b] }=await pool.query('SELECT * FROM bookings WHERE id=$1',[req.params.id]);
  if (!b) return res.status(404).json({ error:'Not found' });
  if (b.guest_user_id!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ error:'Not authorized' });
  const { rows:[u] }=await pool.query(`UPDATE bookings SET status='cancelled',cancelled_at=NOW() WHERE id=$1 RETURNING *`,[req.params.id]);
  res.json(u);
}));

// ── Reviews ───────────────────────────────────────────────────────────────────
app.post('/api/reviews', auth, H(async(req,res)=>{
  const { property_id,rating,comment,booking_id }=req.body;
  if (!property_id||!rating) return res.status(400).json({ error:'Property and rating required' });
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows:[r] }=await client.query(
      `INSERT INTO reviews (property_id,booking_id,guest_user_id,guest_name,rating,comment) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [property_id,booking_id||null,req.user.id,req.user.name,rating,comment||null]
    );
    await client.query(`UPDATE properties SET rating=(SELECT ROUND(AVG(rating)::numeric,1) FROM reviews WHERE property_id=$1),review_count=(SELECT COUNT(*) FROM reviews WHERE property_id=$1) WHERE id=$1`,[property_id]);
    await client.query('COMMIT');
    res.status(201).json(r);
  } catch(e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}));

// ── Payments (dev mode) ───────────────────────────────────────────────────────
app.post('/api/payments/create-order', auth, H(async(req,res)=>{
  const { booking_id }=req.body;
  const { rows:[b] }=await pool.query('SELECT * FROM bookings WHERE id=$1 AND guest_user_id=$2',[booking_id,req.user.id]);
  if (!b) return res.status(404).json({ error:'Booking not found' });
  res.json({ order:{ id:`order_dev_${Date.now()}`,amount:b.total_amount*100,currency:'INR' }, key_id:'rzp_dev_mode' });
}));

app.post('/api/payments/confirm', auth, H(async(req,res)=>{
  const { razorpay_order_id }=req.body;
  const { rows:[b] }=await pool.query(`UPDATE bookings SET payment_status='paid',status='confirmed' WHERE razorpay_order_id=$1 OR id=$1 RETURNING *`,[razorpay_order_id]);
  res.json({ success:true, booking:b });
}));

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', auth, adminOnly, H(async(req,res)=>{
  const [pr,bk,us,rv,tw]=await Promise.all([
    pool.query(`SELECT COUNT(*) total,COUNT(*) FILTER(WHERE status='active') active,COUNT(*) FILTER(WHERE status='pending') pending FROM properties`),
    pool.query(`SELECT COUNT(*) total,COUNT(*) FILTER(WHERE status='confirmed') confirmed,COUNT(*) FILTER(WHERE status='pending_owner') pending_owner FROM bookings`),
    pool.query(`SELECT COUNT(*) total,COUNT(*) FILTER(WHERE role='owner') owners,COUNT(*) FILTER(WHERE role='guest') guests FROM users`),
    pool.query(`SELECT COALESCE(SUM(total_amount),0) total FROM bookings WHERE payment_status='paid'`),
    pool.query(`SELECT town,COUNT(*) count FROM properties WHERE status='active' GROUP BY town ORDER BY count DESC`),
  ]);
  res.json({ properties:pr.rows[0],bookings:bk.rows[0],users:us.rows[0],totalRevenue:parseInt(rv.rows[0].total),townBreakdown:tw.rows });
}));

app.get('/api/admin/bookings', auth, adminOnly, H(async(req,res)=>{
  const { rows }=await pool.query(`SELECT b.*,p.name property_name,p.town,u.name guest_name FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id ORDER BY b.created_at DESC LIMIT 200`);
  res.json(rows);
}));

app.get('/api/admin/pending-bookings', auth, adminOnly, H(async(req,res)=>{
  const { rows }=await pool.query(`SELECT b.*,p.name property_name,p.owner_id,u.name guest_name,ow.name owner_name FROM bookings b JOIN properties p ON p.id=b.property_id JOIN users u ON u.id=b.guest_user_id JOIN users ow ON ow.id=p.owner_id WHERE b.status='pending_owner' AND b.expires_at>NOW() ORDER BY b.expires_at ASC`);
  res.json(rows);
}));

app.put('/api/admin/properties/:id', auth, adminOnly, H(async(req,res)=>{
  const { grade,status }=req.body;
  const u=[],p=[];let i=1;
  if (grade) { u.push(`grade=$${i++}`); p.push(grade); }
  if (status){ u.push(`status=$${i++}`); p.push(status); }
  if (!u.length) return res.status(400).json({ error:'Nothing to update' });
  u.push(`updated_at=NOW()`); p.push(req.params.id);
  const { rows }=await pool.query(`UPDATE properties SET ${u.join(',')} WHERE id=$${i} RETURNING *`,p);
  res.json(rows[0]||{ error:'Not found' });
}));

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err,req,res,_n)=>{
  console.error(err.message);
  res.status(500).json({ error:process.env.NODE_ENV==='production'?'Internal server error':err.message });
});

app.get('/{*splat}',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

// ── Migrate ───────────────────────────────────────────────────────────────────
async function migrate() {
  const c=await pool.connect();
  try {
    console.log('Migrating...');
    await c.query('BEGIN');
    await c.query(`CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),role VARCHAR(20) DEFAULT 'guest',name VARCHAR(200) NOT NULL,email VARCHAR(200) UNIQUE NOT NULL,phone VARCHAR(20),password_hash TEXT NOT NULL,phone_verified BOOLEAN DEFAULT false,email_verified BOOLEAN DEFAULT false,kyc_status VARCHAR(20) DEFAULT 'pending',created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());`);
    await c.query(`CREATE TABLE IF NOT EXISTS properties (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),owner_id UUID NOT NULL REFERENCES users(id),status VARCHAR(20) DEFAULT 'pending',grade VARCHAR(10) DEFAULT 'Bronze',name VARCHAR(200) NOT NULL,type VARCHAR(50) NOT NULL,bhk INTEGER NOT NULL,town VARCHAR(100) NOT NULL,area VARCHAR(200) NOT NULL,address TEXT,distance_note VARCHAR(200),max_guests INTEGER DEFAULT 2,base_price INTEGER DEFAULT 400,parking_type VARCHAR(20) DEFAULT 'none',parking_vehicle VARCHAR(10) DEFAULT 'none',food_option VARCHAR(20) DEFAULT 'none',food_price INTEGER DEFAULT 0,description TEXT,house_rules TEXT,amenities TEXT[] DEFAULT '{}',photos TEXT[] DEFAULT '{}',rating NUMERIC(3,1) DEFAULT 0,review_count INTEGER DEFAULT 0,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());`);
    await c.query(`CREATE TABLE IF NOT EXISTS otp_store (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),phone VARCHAR(20) NOT NULL,otp_hash TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,verified BOOLEAN DEFAULT false,created_at TIMESTAMPTZ DEFAULT NOW());`);
    await c.query(`CREATE TABLE IF NOT EXISTS bookings (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),property_id UUID NOT NULL REFERENCES properties(id),guest_user_id UUID NOT NULL REFERENCES users(id),status VARCHAR(30) DEFAULT 'pending_owner',check_in DATE NOT NULL,check_out DATE NOT NULL,days INTEGER NOT NULL,guest_count INTEGER DEFAULT 1,purpose_of_visit VARCHAR(100),tariff_per_day INTEGER NOT NULL,total_amount INTEGER NOT NULL,breakdown JSONB DEFAULT '[]',parking_type VARCHAR(20) DEFAULT 'none',parking_vehicle VARCHAR(10) DEFAULT 'none',extra_services TEXT[] DEFAULT '{}',expires_at TIMESTAMPTZ,responded_at TIMESTAMPTZ,cancelled_at TIMESTAMPTZ,razorpay_order_id VARCHAR(100),razorpay_payment_id VARCHAR(100),payment_status VARCHAR(20) DEFAULT 'pending',created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW());`);
    await c.query(`CREATE TABLE IF NOT EXISTS guest_verifications (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),booking_id UUID NOT NULL REFERENCES bookings(id),guest_index INTEGER NOT NULL,full_name VARCHAR(200) NOT NULL,govt_id_type VARCHAR(50) NOT NULL,govt_id_number TEXT NOT NULL,phone VARCHAR(20) NOT NULL,email VARCHAR(200) NOT NULL,facebook_url TEXT,linkedin_url TEXT,phone_verified BOOLEAN DEFAULT false,created_at TIMESTAMPTZ DEFAULT NOW());`);
    await c.query(`CREATE TABLE IF NOT EXISTS reviews (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),property_id UUID NOT NULL REFERENCES properties(id),booking_id UUID REFERENCES bookings(id),guest_user_id UUID NOT NULL REFERENCES users(id),guest_name VARCHAR(200) NOT NULL,rating INTEGER NOT NULL,comment TEXT,owner_reply TEXT,created_at TIMESTAMPTZ DEFAULT NOW());`);
    await c.query(`CREATE TABLE IF NOT EXISTS payments (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),booking_id UUID NOT NULL REFERENCES bookings(id),razorpay_order_id VARCHAR(100),razorpay_payment_id VARCHAR(100),amount INTEGER NOT NULL,currency VARCHAR(10) DEFAULT 'INR',status VARCHAR(20) DEFAULT 'created',owner_payout_amount INTEGER,owner_payout_status VARCHAR(20) DEFAULT 'pending',created_at TIMESTAMPTZ DEFAULT NOW());`);

    // Admin
    const ae=process.env.ADMIN_EMAIL||'admin@velizstay.com';
    const ap=process.env.ADMIN_PASSWORD||'VelizAdmin2026!';
    const ex=await c.query('SELECT id FROM users WHERE email=$1',[ae]);
    let aid;
    if (!ex.rows.length) {
      const r=await c.query(`INSERT INTO users (role,name,email,phone,password_hash,phone_verified,email_verified,kyc_status) VALUES ('admin','Veliz Admin',$1,'9999999999',$2,true,true,'verified') RETURNING id`,[ae,bcrypt.hashSync(ap,12)]);
      aid=r.rows[0].id;
      console.log('Admin created:',ae);
    } else { aid=ex.rows[0].id; }

    // Seed properties
    const pc=await c.query('SELECT COUNT(*) FROM properties');
    if (parseInt(pc.rows[0].count)===0) {
      const seeds=[
        ['Nalini Coconut Home','House',2,'Pollachi','Aliyar Road','3.2 km from Pollachi town',4,650,'inside','car','daily_package',300,'Peaceful coconut farm homestead. Home-cooked meals, fresh coconut water daily.','No smoking. Quiet after 10pm.','{wifi,meals,car_parking,power_backup,ac}','Gold',4.9,34],
        ['Selvam Guest House','Apartment',1,'Coimbatore','Peelamedu','0.8 km from Tidel Park',2,480,'road','bike','none',0,'Clean apartment near Coimbatore IT corridor. Ideal for business travelers.','Working professionals preferred.','{wifi,bike_parking,laundry}','Silver',4.7,18],
        ['Valparai Mist Cabin','Cabin',2,'Coimbatore','Valparai','62 km from Pollachi',5,1100,'inside','car','free',0,'Eco-cabin in misty Valparai hills. Free meals, wildlife corridor access.','Eco-stay. No plastic.','{wifi,free_meals,car_parking,security,wildlife_access}','Gold',4.9,52],
        ['Amaravathi Lakeside Stay','House',3,'Pollachi','Amaravathi','8 km from Pollachi town',6,820,'inside','car','pay_per_item',150,'Large 3BHK with stunning lake views. Perfect for group stays.','Groups welcome. No loud music after 9pm.','{wifi,car_parking,power_backup,pay_per_meal}','Silver',4.8,27],
        ['Murugan Nivas Long Stay','House',2,'Udumalpet','Town Centre','0.4 km from bus stand',3,410,'road','bike','none',0,'Affordable central Udumalpet home. Monthly stays preferred.','Monthly stays preferred.','{wifi,bike_parking}','Bronze',4.6,11],
        ['Karpagam Farm Villa','Villa',3,'Pollachi','Topslip Road','5 km from Top Slip',8,1200,'inside','car','free',0,'Premium villa near Anaimalai Tiger Reserve. Free Kongu Nadu meals.','Families and groups only. Min 2 nights.','{wifi,free_meals,car_parking,security,power_backup,ac}','Gold',4.9,61],
      ];
      for (const s of seeds) {
        await c.query(`INSERT INTO properties (owner_id,name,type,bhk,town,area,distance_note,max_guests,base_price,parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities,grade,status,rating,review_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::text[],$17,'active',$18,$19)`,[aid,...s]);
      }
      console.log('6 properties seeded');
    }
    await c.query('COMMIT');
    console.log('Migration done!');
  } catch(e) { await c.query('ROLLBACK'); console.error('Migration error:',e.message); }
  finally { c.release(); }
}

// ── Start — listen FIRST, migrate after ──────────────────────────────────────
app.listen(PORT, async()=>{
  console.log(`\n🏡 Veliz Stay → http://localhost:${PORT} | ENV:${process.env.NODE_ENV||'dev'}`);
  if (process.env.DATABASE_URL) {
    await migrate().catch(e=>console.error('Migration failed:',e.message));
  } else {
    console.log('No DATABASE_URL — skipping migration');
  }
});
