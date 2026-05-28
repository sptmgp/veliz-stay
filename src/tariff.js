// Veliz Stay — Tariff Engine
// Base: owner-set price (min ₹400, max ₹1200)
// Parking: car inside +25%, bike inside +12%, road (either) +15%
// Services: flat per-day add-ons

const SERVICE_RATES = {
  wifi:     200,
  security: 150,
  medical:  100,
  laundry:  120,
};

function calcTariff(basePrice, parkingType, parkingVehicle, services = []) {
  const base = Math.max(400, Math.min(1200, parseInt(basePrice) || 400));
  let total = base;
  const breakdown = [{ label: 'Base tariff (24h checkout)', amount: base }];

  if (parkingVehicle === 'car' && parkingType === 'inside') {
    const add = Math.round(base * 0.25);
    total += add;
    breakdown.push({ label: 'Car parking — inside premises (+25%)', amount: add });
  } else if (parkingVehicle === 'bike' && parkingType === 'inside') {
    const add = Math.round(base * 0.12);
    total += add;
    breakdown.push({ label: 'Two-wheeler parking — inside (+12%)', amount: add });
  } else if (parkingType === 'road') {
    const add = Math.round(base * 0.15);
    total += add;
    const veh = parkingVehicle === 'bike' ? 'two-wheeler' : 'car';
    breakdown.push({ label: `${veh.charAt(0).toUpperCase()+veh.slice(1)} road parking (+15%)`, amount: add });
  }

  for (const svc of services) {
    if (SERVICE_RATES[svc]) {
      total += SERVICE_RATES[svc];
      breakdown.push({ label: `${svc.charAt(0).toUpperCase()+svc.slice(1)} service`, amount: SERVICE_RATES[svc] });
    }
  }

  return { base, total, breakdown };
}

module.exports = { calcTariff, SERVICE_RATES };
