import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export const isAttack = (c) => c !== "normal_request" && c !== "miscellaneous";
export const pct = (n, d) => (d ? Math.round((n / d) * 100) : null);
const TIP = { contentStyle: { background: "#131316", border: "1px solid #26262c", borderRadius: 8 } };

export function lastDays(items, n = 7) {
  const days = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    days.push({ key: d.toDateString(), name: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }), Detected: 0, Blocked: 0 });
  }
  for (const t of items) {
    const row = days.find((d) => d.key === new Date(t.created_at).toDateString());
    if (row && isAttack(t.category)) { if (t.outcome === "FAIL") row.Detected++; if (t.outcome === "PASS") row.Blocked++; }
  }
  return days;
}

export function Donut({ parts, colors, label = "Tests" }) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  const R = 56, C = 2 * Math.PI * R; let off = 0;
  if (!total) return <div className="empty">No data yet.</div>;
  return (
    <div className="donut-wrap">
      <div className="donut">
        <svg viewBox="0 0 140 140" width="150" height="150" role="img" aria-label={label}>
          <circle cx="70" cy="70" r={R} fill="none" stroke="#26262c" strokeWidth="16" />
          {parts.filter((p) => p.value).map((p, i) => { const len = (p.value / total) * C; const el = <circle key={p.name} cx="70" cy="70" r={R} fill="none" stroke={colors[i % colors.length]} strokeWidth="16" strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-off} transform="rotate(-90 70 70)" />; off += len; return el; })}
        </svg>
        <div className="donut-c"><div><b>{total}</b><br />{label}</div></div>
      </div>
      <div className="leg-list">{parts.filter((p) => p.value).map((p, i) => <div key={p.name}><span><i style={{ display: "inline-block", width: 9, height: 9, borderRadius: "50%", background: colors[i % colors.length], marginRight: 8 }} />{p.name}</span><b>{Math.round((p.value / total) * 100)}%</b></div>)}</div>
    </div>
  );
}

export function TrendChart({ data, aKey, bKey, aColor, bColor, aLabel, bLabel }) {
  return (
    <>
      <div className="legend"><span><i style={{ background: aColor }} />{aLabel}</span><span><i style={{ background: bColor }} />{bLabel}</span></div>
      <div className="chart" style={{ height: 170 }}><ResponsiveContainer width="100%" height="100%"><AreaChart data={data}>
        <CartesianGrid stroke="#26262c" vertical={false} /><XAxis dataKey="name" stroke="#9a9aa4" tick={{ fontSize: 10 }} /><YAxis stroke="#9a9aa4" allowDecimals={false} tick={{ fontSize: 10 }} /><Tooltip {...TIP} />
        <Area isAnimationActive={false} type="monotone" dataKey={aKey} stroke={aColor} fill={aColor} fillOpacity={0.12} />
        <Area isAnimationActive={false} type="monotone" dataKey={bKey} stroke={bColor} fill={bColor} fillOpacity={0.08} />
      </AreaChart></ResponsiveContainer></div>
    </>
  );
}

export function CompareBars({ data, aColor, bColor }) {
  return (
    <>
      <div className="legend"><span><i style={{ background: aColor }} />Baseline</span><span><i style={{ background: bColor }} />Defended</span></div>
      <div className="chart" style={{ height: 170 }}><ResponsiveContainer width="100%" height="100%"><BarChart data={data}>
        <CartesianGrid stroke="#26262c" vertical={false} /><XAxis dataKey="name" stroke="#9a9aa4" tick={{ fontSize: 10 }} /><YAxis stroke="#9a9aa4" allowDecimals={false} tick={{ fontSize: 10 }} /><Tooltip {...TIP} cursor={{ fill: "rgba(255,255,255,.04)" }} />
        <Bar isAnimationActive={false} dataKey="Baseline" fill={aColor} /><Bar isAnimationActive={false} dataKey="Defended" fill={bColor} />
      </BarChart></ResponsiveContainer></div>
    </>
  );
}
