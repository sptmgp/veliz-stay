require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function migrate() {
  const client = await pool.connect();
  try {
    console.log('Running Veliz Stay database migration...');
    await client.query('BEGIN');

    // ── Users ──────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role VARCHAR(20) NOT NULL DEFAULT 'guest' CHECK (role IN ('guest','owner','admin')),
        name VARCHAR(200) NOT NULL,
        email VARCHAR(200) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password_hash TEXT NOT NULL,
        phone_verified BOOLEAN DEFAULT false,
        email_verified BOOLEAN DEFAULT false,
        kyc_status VARCHAR(20) DEFAULT 'pending' CHECK (kyc_status IN ('pending','verified','rejected')),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── Properties ─────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS properties (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id UUID NOT NULL REFERENCES users(id),
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending','active','suspended','delisted')),
        grade VARCHAR(10) DEFAULT 'Bronze' CHECK (grade IN ('Bronze','Silver','Gold')),
        name VARCHAR(200) NOT NULL,
        type VARCHAR(50) NOT NULL,
        bhk INTEGER NOT NULL,
        town VARCHAR(100) NOT NULL,
        area VARCHAR(200) NOT NULL,
        address TEXT,
        distance_note VARCHAR(200),
        max_guests INTEGER NOT NULL DEFAULT 2,
        base_price INTEGER NOT NULL DEFAULT 400,
        parking_type VARCHAR(20) DEFAULT 'none' CHECK (parking_type IN ('none','inside','road')),
        parking_vehicle VARCHAR(10) DEFAULT 'none' CHECK (parking_vehicle IN ('none','car','bike')),
        food_option VARCHAR(20) DEFAULT 'none' CHECK (food_option IN ('none','free','pay_per_item','daily_package')),
        food_price INTEGER DEFAULT 0,
        description TEXT,
        house_rules TEXT,
        amenities TEXT[] DEFAULT '{}',
        photos TEXT[] DEFAULT '{}',
        rating NUMERIC(3,1) DEFAULT 0,
        review_count INTEGER DEFAULT 0,
        audit_score INTEGER DEFAULT 70,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── OTP store ──────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS otp_store (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        phone VARCHAR(20) NOT NULL,
        otp_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        verified BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_store(phone);`);

    // ── Bookings ───────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        property_id UUID NOT NULL REFERENCES properties(id),
        guest_user_id UUID NOT NULL REFERENCES users(id),
        status VARCHAR(30) DEFAULT 'pending_owner' CHECK (status IN (
          'pending_owner','confirmed','declined','expired','cancelled','completed'
        )),
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
        payment_status VARCHAR(20) DEFAULT 'pending' CHECK (payment_status IN ('pending','paid','refunded','failed')),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── Guest verification details (separate for privacy) ──────────────────────
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
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_gv_booking ON guest_verifications(booking_id);`);

    // ── Reviews ────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        property_id UUID NOT NULL REFERENCES properties(id),
        booking_id UUID REFERENCES bookings(id),
        guest_user_id UUID NOT NULL REFERENCES users(id),
        guest_name VARCHAR(200) NOT NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        owner_reply TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_reviews_prop ON reviews(property_id);`);

    // ── Payments ────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        booking_id UUID NOT NULL REFERENCES bookings(id),
        razorpay_order_id VARCHAR(100),
        razorpay_payment_id VARCHAR(100),
        amount INTEGER NOT NULL,
        currency VARCHAR(10) DEFAULT 'INR',
        status VARCHAR(20) DEFAULT 'created' CHECK (status IN ('created','paid','failed','refunded')),
        owner_payout_amount INTEGER,
        owner_payout_status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── Audit log ──────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        admin_id UUID REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        entity_type VARCHAR(50),
        entity_id UUID,
        details JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── Seed admin ──────────────────────────────────────────────────────────────
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@velizstay.com';
    const adminPass  = process.env.ADMIN_PASSWORD || 'VelizAdmin2026!';
    const existing   = await client.query('SELECT id FROM users WHERE email=$1', [adminEmail]);
    if (!existing.rows.length) {
      const hash = bcrypt.hashSync(adminPass, 12);
      await client.query(
        `INSERT INTO users (role,name,email,phone,password_hash,phone_verified,email_verified,kyc_status)
         VALUES ('admin','Veliz Admin',$1,'9999999999',$2,true,true,'verified')`,
        [adminEmail, hash]
      );
      console.log(`Admin created: ${adminEmail}`);
    }

    // ── Seed sample properties ─────────────────────────────────────────────────
    const propCount = await client.query('SELECT COUNT(*) FROM properties');
    if (parseInt(propCount.rows[0].count) === 0) {
      const adminUser = await client.query('SELECT id FROM users WHERE email=$1', [adminEmail]);
      const ownerId = adminUser.rows[0].id;
      const seeds = [
        ['Nalini Coconut Home','House',2,'Pollachi','Aliyar Road','3.2 km from Pollachi town',4,650,'inside','car','daily_package',300,'Peaceful coconut farm homestead. Home-cooked meals, fresh coconut water daily.','No smoking. Quiet after 10pm.','{wifi,meals,car_parking,power_backup,ac}','Gold'],
        ['Selvam Guest House','Apartment',1,'Coimbatore','Peelamedu','0.8 km from Tidel Park',2,480,'road','bike','none',0,'Clean apartment near Coimbatore IT corridor. Ideal for business travelers.','Working professionals preferred.','{wifi,bike_parking,laundry}','Silver'],
        ['Valparai Mist Cabin','Cabin',2,'Coimbatore','Valparai','62 km from Pollachi',5,1100,'inside','car','free',0,'Eco-cabin in the misty Valparai hills. Free meals, wildlife corridor access.','Eco-stay. No plastic. Lights out by 11pm.','{wifi,free_meals,car_parking,security,wildlife_access}','Gold'],
        ['Amaravathi Lakeside Stay','House',3,'Pollachi','Amaravathi','8 km from Pollachi town',6,820,'inside','car','pay_per_item',150,'Large 3BHK with stunning lake views. Perfect for groups and family stays.','Groups welcome. No loud music after 9pm.','{wifi,car_parking,power_backup,pay_per_meal}','Silver'],
        ['Murugan Nivas Long Stay','House',2,'Udumalpet','Town Centre','0.4 km from bus stand',3,410,'road','bike','none',0,'Affordable central Udumalpet home. Monthly stays preferred.','Monthly stays preferred. Working adults only.','{wifi,bike_parking}','Bronze'],
        ['Karpagam Farm Villa','Villa',3,'Pollachi','Topslip Road','5 km from Top Slip',8,1200,'inside','car','free',0,'Premium villa on a working farm near Anaimalai Tiger Reserve. Free Kongu Nadu meals.','Families and groups only. Min 2 night stay.','{wifi,free_meals,car_parking,security,power_backup,ac}','Gold']
      ];
      for (const s of seeds) {
        await client.query(
          `INSERT INTO properties (owner_id,name,type,bhk,town,area,distance_note,max_guests,base_price,
           parking_type,parking_vehicle,food_option,food_price,description,house_rules,amenities,grade,status,rating,review_count)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::text[],$17,'active',4.8,12)`,
          [ownerId, ...s]
        );
      }
      console.log('Sample properties seeded');
    }

    await client.query('COMMIT');
    console.log('Migration complete!');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Migration failed:', err.message);
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

migrate().catch(() => process.exit(1));
