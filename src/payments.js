const crypto = require('crypto');
const pool = require('./db');

function getRazorpay() {
  if (!process.env.RAZORPAY_KEY_ID || process.env.RAZORPAY_KEY_ID.startsWith('rzp_live_REPLACE')) {
    return null; // not configured
  }
  const Razorpay = require('razorpay');
  return new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
}

async function createOrder(bookingId, amountINR) {
  const rzp = getRazorpay();
  if (!rzp) {
    // Dev mode — return mock order
    const mockOrder = { id: `order_dev_${Date.now()}`, amount: amountINR * 100, currency: 'INR', status: 'created' };
    await pool.query(`UPDATE bookings SET razorpay_order_id=$1 WHERE id=$2`, [mockOrder.id, bookingId]);
    return mockOrder;
  }
  const order = await rzp.orders.create({ amount: amountINR * 100, currency: 'INR', receipt: bookingId });
  await pool.query(
    `INSERT INTO payments (booking_id, razorpay_order_id, amount, status) VALUES ($1,$2,$3,'created')`,
    [bookingId, order.id, amountINR]
  );
  await pool.query(`UPDATE bookings SET razorpay_order_id=$1 WHERE id=$2`, [order.id, bookingId]);
  return order;
}

function verifySignature(orderId, paymentId, signature) {
  const key = process.env.RAZORPAY_KEY_SECRET;
  if (!key) return true; // dev mode
  const body = `${orderId}|${paymentId}`;
  const expected = crypto.createHmac('sha256', key).update(body).digest('hex');
  return expected === signature;
}

async function confirmPayment(orderId, paymentId, signature) {
  if (!verifySignature(orderId, paymentId, signature)) {
    throw new Error('Payment signature verification failed');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const booking = await client.query(
      `UPDATE bookings SET razorpay_payment_id=$1, payment_status='paid', status='confirmed'
       WHERE razorpay_order_id=$2 RETURNING *, total_amount`,
      [paymentId, orderId]
    );
    if (!booking.rows.length) throw new Error('Booking not found for order');
    const b = booking.rows[0];
    const ownerCut = Math.round(b.total_amount * 0.75); // 75% to owner
    await client.query(
      `UPDATE payments SET razorpay_payment_id=$1, status='paid',
       owner_payout_amount=$2, owner_payout_status='pending'
       WHERE razorpay_order_id=$3`,
      [paymentId, ownerCut, orderId]
    );
    await client.query('COMMIT');
    return b;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { createOrder, confirmPayment, verifySignature, getRazorpay };
