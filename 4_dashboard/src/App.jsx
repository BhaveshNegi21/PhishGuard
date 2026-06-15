import "./App.css";
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield,
  Search,
  Download,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
    Clock,
  BarChart2,
  RefreshCw,
  Globe,
    Zap,
  Lock,
  FileText,
  TrendingUp,
  TrendingDown,
  ShieldCheck,
    ShieldAlert,
  Percent,
} from "lucide-react";
import {
  PieChart, Pie, Cell,
  ResponsiveContainer,
  LineChart, Line,
  AreaChart, Area,
  XAxis, YAxis,
  CartesianGrid,
  Tooltip, Legend,
} from "recharts";

/**
 * Builds last-7-days scan volume data from real scan history.
 * Groups scans by calendar day and counts totals vs threats.
 */
function buildScanVolumeData(history) {
  const days = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(now.getDate() - i);
    days.push({
      date: d,
      label: d.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      scans: 0,
      threats: 0,
    });
  }

  history.forEach((row) => {
    // timestamp may be "YYYY-MM-DD HH:MM:SS" or locale string
    const ts = new Date(row.timestamp);
    if (isNaN(ts.getTime())) return;
    const dayStr = ts.toLocaleDateString("en-US", { month: "short", day: "numeric" });
    const slot = days.find((d) => d.label === dayStr);
    if (slot) {
      slot.scans += 1;
      if (row.status === "Malicious") slot.threats += 1;
    }
  });

  return days.map(({ label, scans, threats }) => ({ day: label, scans, threats }));
}

/**
 * Builds a 7-point sparkline from history grouped by last 7 days.
 * Returns array of counts per day (oldest → newest).
 */
function buildSparkline(history, filterFn) {
  const days = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(now.getDate() - i);
    days.push({
      label: d.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      count: 0,
    });
  }
  history.forEach((row) => {
    if (!filterFn(row)) return;
    const ts = new Date(row.timestamp);
    if (isNaN(ts.getTime())) return;
    const dayStr = ts.toLocaleDateString("en-US", { month: "short", day: "numeric" });
    const slot = days.find((d) => d.label === dayStr);
    if (slot) slot.count += 1;
  });
  return days.map((d) => d.count);
}

const mockApiScan = (url) => {
  const phishSignals = [
    /\.(ru|tk|xyz|ml|gq|cf|online)\b/i,
    /\b(login|verify|suspended|alert|update|claim|winner|secure-.*\.(?!com))/i,
    /paypa[l1]|m[i1]crosoft|g[o0]{2}gle|arnazon|faceb[o0]{2}k/i,
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  ];
  const isPhishing = phishSignals.some((p) => p.test(url));

  return {
    url,
    is_phishing: isPhishing,
    confidence_score: isPhishing
      ? parseFloat((Math.random() * 9 + 90).toFixed(1))
        : parseFloat((Math.random() * 3).toFixed(1)),
    threat_category: isPhishing
      ? ["Credential Phishing", "Brand Impersonation", "Scam / Giveaway", "Malware Distribution"][
          Math.floor(Math.random() * 4)
        ]
      : "Legitimate",
    domain_age_days: isPhishing
        ? Math.floor(Math.random() * 30)
      : Math.floor(Math.random() * 2000) + 365,
    ssl_valid: !isPhishing || Math.random() > 0.6,
    redirect_count: isPhishing ? Math.floor(Math.random() * 5) + 1 : 0,
    scan_id: "SCAN-" + Math.random().toString(36).substring(2, 10).toUpperCase(),
      scanned_at: new Date().toLocaleString("en-GB").replace(",", ""),
  };
};

const exportToCSV = (rows) => {
  const HEADERS = ["URL", "Status", "Threat Level", "Confidence (%)", "Category", "Timestamp"];
    const escape = (v) => `"${String(v).replace(/"/g, '""')}"`;
  const csvLines = [
    HEADERS.join(","),
    ...rows.map((r) =>
      [
          escape(r.url),
        r.status,
        r.threatLevel,
        r.confidence,
          escape(r.category),
        r.timestamp,
      ].join(",")
    ),
  ];
  const blob = new Blob([csvLines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const href = URL.createObjectURL(blob);
  const anchor = Object.assign(document.createElement("a"), {
    href,
    download: `phishguard_report_${new Date().toISOString().slice(0, 10)}.csv`,
  });
  document.body.appendChild(anchor);
    anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(href);
};

const chartTooltipStyle = {
  contentStyle: {
      background: "#ffffff",
    border: "1px solid #e5e7eb",
    borderRadius: "10px",
    fontSize: "12px",
      color: "#374151",
    boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
  },
  labelStyle: { color: "#6b7280", fontWeight: 600 },
    cursor: { stroke: "#e5e7eb", strokeWidth: 1 },
};

const StatusBadge = ({ status }) =>
  status === "Malicious" ? (
    <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold bg-red-50 text-red-600 border border-red-200">
      <XCircle size={11} aria-hidden="true" />
      Malicious
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
        <CheckCircle size={11} aria-hidden="true" />
      Clean
    </span>
  );

const ThreatBadge = ({ level }) =>
  level === "High" ? (
      <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold bg-rose-50 text-rose-600 border border-rose-200">
      <ShieldAlert size={11} aria-hidden="true" />
      High
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold bg-blue-50 text-blue-600 border border-blue-200">
      <ShieldCheck size={11} aria-hidden="true" />
        Low
    </span>
  );

const ConfidenceBar = ({ value, isThreat }) => {
  const [width, setWidth] = useState(0);
    useEffect(() => {
    const t = requestAnimationFrame(() => setWidth(value));
    return () => cancelAnimationFrame(t);
  }, [value]);

  return (
    <div className="flex items-center gap-2 min-w-[110px]">
        <div className="flex-1 h-1.5 rounded-full bg-gray-100 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${
              isThreat ? "bg-rose-500" : "bg-emerald-500"
          }`}
          style={{ width: `${width}%` }}
        />
      </div>
      <span
          className={`font-mono text-[11px] font-semibold w-10 text-right ${
          isThreat ? "text-rose-600" : "text-emerald-600"
        }`}
      >
        {value}%
      </span>
    </div>
  );
};

function SectionHeader({ icon, title, badge }) {
    return (
    <div className="flex items-center gap-2">
      <span className="text-blue-600">{icon}</span>
        <h2 className="text-sm font-semibold text-gray-800">{title}</h2>
      {badge && (
        <span className="ml-auto rounded-full bg-gray-100 px-2.5 py-0.5 text-[10px] font-medium text-gray-500">
          {badge}
        </span>
      )}
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
      <div className="flex flex-col items-center rounded-xl bg-gray-50 border border-gray-100 py-3">
      <span className={`font-mono text-2xl font-bold leading-none ${color}`}>{value}</span>
        <span className="mt-1 text-[10px] font-medium uppercase tracking-wider text-gray-400">{label}</span>
    </div>
  );
}

function LiveClock() {
  const [time, setTime] = useState(
    () =>
      new Date().toLocaleTimeString("en-GB", {
          hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
  );
  useEffect(() => {
    const id = setInterval(
        () =>
        setTime(
          new Date().toLocaleTimeString("en-GB", {
            hour: "2-digit",
              minute: "2-digit",
            second: "2-digit",
          })
        ),
      1000
    );
      return () => clearInterval(id);
  }, []);
  return <time>{time}</time>;
}

const PieSliceLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
  const RAD = Math.PI / 180;
    const r = innerRadius + (outerRadius - innerRadius) * 0.55;
  const x = cx + r * Math.cos(-midAngle * RAD);
  const y = cy + r * Math.sin(-midAngle * RAD);
  return (
    <text x={x} y={y} textAnchor="middle" dominantBaseline="central" fill="white" fontSize={11} fontWeight="700">
        {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

function Sparkline({ data, color, fillColor }) {
  return (
    <ResponsiveContainer width="100%" height={48}>
        <AreaChart data={data.map((v, i) => ({ v, i }))} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
        <defs>
            <linearGradient id={`grad-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={fillColor} stopOpacity={0.25} />
            <stop offset="95%" stopColor={fillColor} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area
          type="monotone"
          dataKey="v"
            stroke={color}
          strokeWidth={2}
          fill={`url(#grad-${color.replace("#", "")})`}
          dot={false}
          activeDot={false}
          isAnimationActive={true}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function KPICard({ title, value, unit, trend, trendUp, icon: Icon, iconBg, sparkData, sparkColor }) {
  return (
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-5 flex flex-col gap-3 hover:shadow-md transition-shadow duration-200">
      <div className="flex items-start justify-between">
        <div>
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{title}</p>
          <p className="mt-1.5 text-3xl font-bold text-gray-900 leading-none">
            {value}
              {unit && <span className="text-lg font-semibold text-gray-400 ml-1">{unit}</span>}
          </p>
        </div>
        <div className={`p-2.5 rounded-xl ${iconBg}`}>
            <Icon size={18} className="text-white" aria-hidden="true" />
        </div>
      </div>

      <div className="-mx-1">
          <Sparkline data={sparkData} color={sparkColor} fillColor={sparkColor} />
      </div>

      <div className="flex items-center gap-1.5">
        {trendUp ? (
            <TrendingUp size={13} className="text-emerald-500" aria-hidden="true" />
        ) : (
          <TrendingDown size={13} className="text-red-500" aria-hidden="true" />
        )}
        <span className={`text-xs font-semibold ${trendUp ? "text-emerald-600" : "text-red-500"}`}>
            {trend}
        </span>
        <span className="text-xs text-gray-400">vs last week</span>
      </div>
    </div>
  );
}

const ScanResultCard = ({ result }) => {
  const [visible, setVisible] = useState(false);
    useEffect(() => {
    if (result) {
      setVisible(false);
        const t = setTimeout(() => setVisible(true), 50);
      return () => clearTimeout(t);
    }
  }, [result]);

  if (!result) return null;
    const threat = result.is_phishing;

  return (
    <div
      className={`mt-4 rounded-xl border-l-4 bg-white border border-gray-200 shadow-sm p-4 transition-all duration-500 ${
          visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"
      } ${threat ? "border-l-red-500" : "border-l-emerald-500"}`}
    >
      <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
          {threat ? (
            <AlertTriangle size={15} className="text-red-500" aria-hidden="true" />
          ) : (
              <Shield size={15} className="text-emerald-500" aria-hidden="true" />
          )}
          <span className={`font-bold text-xs tracking-wide ${threat ? "text-red-600" : "text-emerald-600"}`}>
            {threat ? "⚠ Threat Detected" : "✓ URL is Clean"}
          </span>
        </div>
        <span className="text-[10px] font-mono text-gray-400 bg-gray-50 border border-gray-200 px-2 py-0.5 rounded">
            {result.scan_id}
        </span>
      </div>

      <div className="mb-3">
          <div className="flex justify-between items-center mb-1.5">
          <span className="text-[11px] text-gray-500 font-medium">Confidence Score</span>
          <span className={`text-xs font-mono font-bold ${threat ? "text-red-600" : "text-emerald-600"}`}>
              {result.confidence_score}%
          </span>
        </div>
        <div className="h-1.5 w-full rounded-full bg-gray-100 overflow-hidden">
          <div
              className={`h-full rounded-full transition-all duration-700 ${
              threat ? "bg-red-500" : "bg-emerald-500"
            }`}
            style={{ width: `${result.confidence_score}%` }}
          />
        </div>
      </div>

        <div className="grid grid-cols-2 gap-2">
        {[
          ["Category", result.threat_category],
            ["Domain Age", `${result.domain_age_days} days`],
          ["SSL Valid", result.ssl_valid ? "✓ Yes" : "✗ No"],
          ["Redirects", String(result.redirect_count)],
        ].map(([label, val]) => (
            <div key={label} className="rounded-lg bg-gray-50 border border-gray-100 px-3 py-2">
            <div className="text-[9px] font-semibold uppercase tracking-widest text-gray-400">{label}</div>
              <div className="text-xs font-medium text-gray-700 mt-0.5 truncate">{val}</div>
          </div>
        ))}
      </div>

      <details className="mt-3">
          <summary className="text-[10px] font-mono text-gray-400 cursor-pointer select-none hover:text-gray-600 transition-colors">
          Raw JSON response ↓
        </summary>
        <pre className="mt-2 text-[10px] font-mono text-gray-500 bg-gray-50 border border-gray-200 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(result, null, 2)}
        </pre>
      </details>
    </div>
  );
};

export default function Dashboard() {
  const [scanInput, setScanInput] = useState("");
    const [isScanning, setIsScanning] = useState(false);
  const [scanStepIdx, setScanStepIdx] = useState(0);
  const [scanResult, setScanResult] = useState(null);
    const [history, setHistory] = useState([]);
  const [activeCount, setActiveCount] = useState(0);
  const [exportFlash, setExportFlash] = useState(false);

  // Tracks arrival times (Date.now()) of each new scan detected from the backend
  const scanArrivalTimes = useRef([]);
  // Tracks the set of scan IDs already seen, so we only count genuinely new ones
  const seenScanIds = useRef(new Set());

  // Every second, expire arrivals older than 5 s and update the displayed count
  useEffect(() => {
    const id = setInterval(() => {
      const cutoff = Date.now() - 5000;
      scanArrivalTimes.current = scanArrivalTimes.current.filter((t) => t > cutoff);
      setActiveCount(scanArrivalTimes.current.length);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const SCAN_STEPS = [
      "Resolving DNS records…",
    "Querying blacklist feeds…",
    "Analysing page content…",
      "Checking SSL certificate…",
    "Scoring with ML model…",
  ];

  useEffect(() => {
    if (!isScanning) { setScanStepIdx(0); return; }
      const id = setInterval(
      () => setScanStepIdx((i) => (i + 1) % SCAN_STEPS.length),
      520
    );
    return () => clearInterval(id);
  }, [isScanning]);

  useEffect(() => {
    // On mount, fetch immediately
    const fetchScans = async () => {
      try {
        const response = await fetch("http://localhost:8000/scans");
        const data = await response.json();
        if (Array.isArray(data) && data.length > 0) {
          // Detect genuinely new scan IDs and record their arrival time
          const now = Date.now();
          data.forEach((r) => {
            if (!seenScanIds.current.has(r.id)) {
              seenScanIds.current.add(r.id);
              // Skip recording on the very first fetch (page load) —
              // those are historical scans, not live activity
              if (seenScanIds.current.size > data.length) {
                scanArrivalTimes.current.push(now);
              }
            }
          });
          // First fetch: seed seenScanIds without triggering active count
          // (handled above via size check, but also mark first-load done)

          // Merge backend scans with any locally-added ones (e.g. manual scanner)
          setHistory((prev) => {
            const backendIds = new Set(data.map((r) => r.id));
            const localOnly = prev.filter((r) => !backendIds.has(r.id));
            return [...localOnly, ...data].sort(
              (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
            );
          });
        }
      } catch (e) {
        console.log("Backend sync failed");
      }
    };
    fetchScans();
    const intervalId = setInterval(fetchScans, 3000);
    return () => clearInterval(intervalId);
  }, []);

  const handleScan = useCallback(
    async (e) => {
        e.preventDefault();
      const url = scanInput.trim();
      if (!url) return;

        setIsScanning(true);
      setScanResult(null);

      await new Promise((r) => setTimeout(r, 2200));

        const result = mockApiScan(url);
      setScanResult(result);
      setIsScanning(false);

      setHistory((prev) => [
          {
          id: Date.now(),
          url,
            status: result.is_phishing ? "Malicious" : "Clean",
          threatLevel: result.is_phishing ? "High" : "Low",
          confidence: result.confidence_score,
            category: result.threat_category,
          timestamp: result.scanned_at,
        },
        ...prev,
      ]);
      setScanInput("");
    },
    [scanInput]
  );

  const handleExport = () => {
      exportToCSV(history);
    setExportFlash(true);
    setTimeout(() => setExportFlash(false), 1500);
  };

  const malCount = history.filter((r) => r.status === "Malicious").length;
  const cleanCount = history.filter((r) => r.status === "Clean").length;
  const total = history.length;
  const detectionRate = total > 0 ? ((malCount / total) * 100).toFixed(1) : "0.0";

  // Real sparklines derived from actual history
  const sparkScans   = buildSparkline(history, () => true);
  const sparkThreats = buildSparkline(history, (r) => r.status === "Malicious");
  const sparkClean   = buildSparkline(history, (r) => r.status === "Clean");
  // Detection-rate sparkline: daily detection rate (%) for each of last 7 days
  const sparkRate = (() => {
    const volumeData = buildScanVolumeData(history);
    return volumeData.map((d) =>
      d.scans > 0 ? parseFloat(((d.threats / d.scans) * 100).toFixed(1)) : 0
    );
  })();

  const pieData = [
    { name: "Phishing",   value: malCount,   color: "#f43f5e" },
    { name: "Legitimate", value: cleanCount, color: "#6366f1" },
  ];

  // Scan volume chart derived from real history
  const scanVolumeData = buildScanVolumeData(history);

  const KPI_CARDS = [
    {
      title: "Total Scans",
      value: total,
      icon: Activity,
      iconBg: "bg-blue-600",
      trend: total > 0 ? `${total} scans total` : "No data yet",
      trendUp: true,
      sparkData: sparkScans,
      sparkColor: "#6366f1",
    },
    {
      title: "Threats Detected",
      value: malCount,
      icon: ShieldAlert,
      iconBg: "bg-rose-500",
      trend: malCount > 0 ? `${malCount} phishing URLs` : "No threats yet",
      trendUp: false,
      sparkData: sparkThreats,
      sparkColor: "#f43f5e",
    },
    {
      title: "Clean URLs",
      value: cleanCount,
      icon: ShieldCheck,
      iconBg: "bg-emerald-500",
      trend: cleanCount > 0 ? `${cleanCount} safe URLs` : "No data yet",
      trendUp: true,
      sparkData: sparkClean,
      sparkColor: "#10b981",
    },
    {
      title: "Detection Rate",
      value: detectionRate,
      unit: "%",
      icon: Percent,
      iconBg: "bg-violet-500",
      trend: total > 0 ? `${detectionRate}% of all scans` : "No data yet",
      trendUp: parseFloat(detectionRate) < 50,
      sparkData: sparkRate,
      sparkColor: "#8b5cf6",
    },
  ];

  return (
    <div className="min-h-screen bg-[#f4f6f8] antialiased flex flex-col">

      <header className="sticky top-0 z-40 bg-white border-b border-gray-200 shadow-sm">
          <div className="flex items-center gap-4 px-6 py-3.5">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-8 h-8 rounded-xl bg-blue-600 shadow-sm shadow-blue-200">
                <Shield size={16} className="text-white" aria-hidden="true" />
            </div>
            <div>
                <h1 className="text-sm font-bold text-gray-900 leading-tight">PhishGuard</h1>
              <p className="text-[10px] text-gray-400 leading-tight">Intelligence Hub · SOC Platform</p>
            </div>
          </div>

            <div className="ml-auto flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5">
              <span
                  className={`h-2 w-2 rounded-full ${
                  activeCount > 0 ? "bg-emerald-400 animate-pulse" : "bg-gray-300"
                }`}
              />
              <span className="text-xs text-gray-500 font-medium">
                  {activeCount} active scan{activeCount !== 1 ? "s" : ""}
              </span>
            </div>

              <div className="hidden md:flex items-center gap-1.5 text-xs text-gray-400 font-mono bg-gray-50 border border-gray-200 px-2.5 py-1.5 rounded-lg">
              <Clock size={12} aria-hidden="true" />
                <LiveClock />
            </div>
          </div>
        </div>
      </header>

        <main className="flex-1 overflow-y-auto p-6 space-y-6 min-w-0">

        <section aria-label="Key Performance Indicators">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {KPI_CARDS.map((card) => (
                <KPICard key={card.title} {...card} />
            ))}
          </div>
        </section>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">

          <section
            className="lg:col-span-1 rounded-2xl border border-gray-200 bg-white shadow-sm p-5"
              aria-label="Manual URL Scanner"
          >
            <SectionHeader icon={<Search size={15} />} title="Manual URL Scanner" />

              <form onSubmit={handleScan} className="mt-4 space-y-3" noValidate>
              <div className="relative">
                <Globe
                    size={13}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none"
                  aria-hidden="true"
                />
                  <input
                  type="url"
                  value={scanInput}
                    onChange={(e) => setScanInput(e.target.value)}
                  placeholder="https://suspicious-site.example"
                  aria-label="URL to scan"
                    disabled={isScanning}
                  className="w-full rounded-xl border border-gray-200 bg-white py-2.5 pl-8 pr-4 text-sm text-gray-800 placeholder-gray-400 outline-none transition-all focus:border-blue-400 focus:ring-2 focus:ring-blue-100 disabled:opacity-50 disabled:bg-gray-50"
                />
              </div>

                <button
                type="submit"
                disabled={isScanning || !scanInput.trim()}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 py-2.5 text-sm font-semibold text-white transition-all hover:bg-blue-700 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 shadow-sm shadow-blue-200"
              >
                {isScanning ? (
                    <>
                    <RefreshCw size={14} className="animate-spin" aria-hidden="true" />
                    Analysing…
                  </>
                ) : (
                  <>
                      <Zap size={14} aria-hidden="true" />
                    Scan URL
                  </>
                )}
              </button>
            </form>

            {isScanning && (
                <div className="mt-4 space-y-1.5 p-3 rounded-xl bg-blue-50 border border-blue-100" role="status" aria-live="polite">
                {SCAN_STEPS.map((step, i) => (
                  <div
                      key={step}
                    className={`flex items-center gap-2 text-[11px] transition-all duration-300 ${
                        i === scanStepIdx
                        ? "text-blue-700 opacity-100 font-semibold"
                        : "text-blue-300 opacity-50"
                    }`}
                  >
                    <span
                        className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${
                        i === scanStepIdx ? "bg-blue-500 animate-pulse" : "bg-blue-200"
                      }`}
                    />
                    {step}
                  </div>
                ))}
              </div>
            )}

              <ScanResultCard result={scanResult} />

            <div className="mt-5 grid grid-cols-2 gap-3 border-t border-gray-100 pt-4">
                <MiniStat label="Threats Found" value={malCount} color="text-red-500" />
              <MiniStat label="Clean Scans" value={cleanCount} color="text-emerald-600" />
            </div>
          </section>

            <div className="lg:col-span-2 grid grid-rows-2 gap-6">

            <section
                className="rounded-2xl border border-gray-200 bg-white shadow-sm p-5"
              aria-label="Risk Distribution Chart"
            >
                <SectionHeader
                icon={<BarChart2 size={15} />}
                title="Risk Distribution"
                  badge="All-time"
              />
              <div className="mt-3 flex items-center gap-6" style={{ height: 160 }}>
                <ResponsiveContainer width="45%" height="100%">
                  <PieChart>
                    {total === 0 ? (
                      <Pie
                        data={[{ name: "No Data", value: 1 }]}
                        cx="50%"
                        cy="50%"
                        outerRadius={68}
                        innerRadius={42}
                        dataKey="value"
                        labelLine={false}
                        strokeWidth={0}
                      >
                        <Cell fill="#e5e7eb" stroke="transparent" />
                      </Pie>
                    ) : (
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        outerRadius={68}
                        innerRadius={42}
                        paddingAngle={3}
                        dataKey="value"
                        labelLine={false}
                        label={PieSliceLabel}
                        strokeWidth={0}
                      >
                        {pieData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} stroke="transparent" />
                        ))}
                      </Pie>
                    )}
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>

                <div className="flex-1 space-y-3">
                  {total === 0 ? (
                    <p className="text-xs text-gray-400 italic">No scan data yet. Browse the web with the extension active or scan a URL manually.</p>
                  ) : (
                    pieData.map((d) => {
                      const pct = ((d.value / total) * 100).toFixed(0);
                      return (
                        <div key={d.name}>
                          <div className="flex justify-between text-xs mb-1.5">
                            <div className="flex items-center gap-2">
                              <span className="h-2.5 w-2.5 rounded-full flex-shrink-0" style={{ background: d.color }} />
                              <span className="text-gray-600 font-medium">{d.name}</span>
                            </div>
                            <span className="font-semibold" style={{ color: d.color }}>
                              {d.value.toLocaleString()}
                            </span>
                          </div>
                          <div className="h-1.5 rounded-full bg-gray-100">
                            <div
                              className="h-full rounded-full transition-all duration-700"
                              style={{ width: `${pct}%`, background: d.color }}
                            />
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </section>

              <section
              className="rounded-2xl border border-gray-200 bg-white shadow-sm p-5"
              aria-label="Scan Volume Chart"
            >
                <SectionHeader
                icon={<Activity size={15} />}
                title="Scan Volume"
                badge="Last 7 days"
              />
                <div className="mt-3" style={{ height: 130 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                      data={scanVolumeData}
                    margin={{ top: 4, right: 8, left: -22, bottom: 0 }}
                  >
                      <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" vertical={false} />
                    <XAxis
                        dataKey="day"
                      tick={{ fill: "#9ca3af", fontSize: 10 }}
                      axisLine={{ stroke: "#e5e7eb" }}
                        tickLine={false}
                    />
                    <YAxis
                        tick={{ fill: "#9ca3af", fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                    />
                      <Tooltip {...chartTooltipStyle} />
                    <Legend
                        iconType="circle"
                      iconSize={7}
                      wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }}
                    />
                      <Line
                      type="monotone"
                      dataKey="scans"
                        name="Total Scans"
                      stroke="#6366f1"
                      strokeWidth={2.5}
                        dot={{ fill: "#6366f1", r: 3, strokeWidth: 0 }}
                      activeDot={{ r: 5, strokeWidth: 2, stroke: "#fff" }}
                    />
                    <Line
                        type="monotone"
                      dataKey="threats"
                      name="Threats"
                        stroke="#f43f5e"
                      strokeWidth={2}
                      strokeDasharray="5 3"
                        dot={{ fill: "#f43f5e", r: 3, strokeWidth: 0 }}
                      activeDot={{ r: 5, strokeWidth: 2, stroke: "#fff" }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </section>
          </div>
        </div>

          <section
          className="rounded-2xl border border-gray-200 bg-white shadow-sm overflow-hidden"
          aria-label="Recent Scans Table"
        >
          <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
              <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-blue-50">
                  <Lock size={14} className="text-blue-600" aria-hidden="true" />
              </div>
              <h2 className="text-sm font-semibold text-gray-800">Recent Scans</h2>
                <span className="ml-1 rounded-full bg-gray-100 px-2.5 py-0.5 font-mono text-[10px] font-medium text-gray-500">
                {history.length} entries
              </span>
            </div>

            <button
                onClick={handleExport}
              className={`inline-flex items-center gap-2 rounded-xl border px-3.5 py-1.5 text-xs font-semibold transition-all duration-200 ${
                  exportFlash
                  ? "border-emerald-300 bg-emerald-50 text-emerald-600"
                  : "border-gray-200 bg-white text-gray-600 hover:border-gray-300 hover:bg-gray-50 hover:text-gray-800 shadow-sm"
              }`}
              aria-label="Export threat report as CSV"
            >
              {exportFlash ? (
                  <>
                  <CheckCircle size={13} aria-hidden="true" />
                  Exported!
                </>
              ) : (
                <>
                    <Download size={13} aria-hidden="true" />
                  Export Report
                </>
              )}
            </button>
          </div>

            <div className="overflow-x-auto table-scroll">
            <table className="w-full min-w-[700px] text-xs">
              <thead>
                  <tr className="bg-gray-50 border-b border-gray-100">
                  {["URL", "Status", "Threat Level", "Confidence", "Category", "Timestamp"].map(
                    (col) => (
                        <th
                        key={col}
                        scope="col"
                        className="px-6 py-3 text-left text-[10px] font-bold uppercase tracking-wider text-gray-400"
                      >
                        {col}
                      </th>
                    )
                  )}
                </tr>
              </thead>
                <tbody>
                {history.map((row, idx) => {
                  const threat = row.status === "Malicious";
                  return (
                      <tr
                      key={row.id}
                      className={`border-b border-gray-50 transition-colors hover:bg-blue-50/30 ${
                          idx % 2 === 0 ? "bg-white" : "bg-gray-50/40"
                      }`}
                    >
                      <td className="max-w-[220px] truncate px-6 py-3.5">
                          <span
                          className={`text-xs font-mono ${
                              threat ? "text-red-500" : "text-gray-600"
                          }`}
                          title={row.url}
                        >
                          {row.url}
                        </span>
                      </td>

                        <td className="px-6 py-3.5">
                        <StatusBadge status={row.status} />
                      </td>

                      <td className="px-6 py-3.5">
                          <ThreatBadge level={row.threatLevel} />
                      </td>

                        <td className="px-6 py-3.5">
                        <ConfidenceBar value={row.confidence} isThreat={threat} />
                      </td>

                      <td className="px-6 py-3.5 text-gray-500 font-medium">{row.category}</td>

                        <td className="px-6 py-3.5 font-mono text-gray-400 whitespace-nowrap">
                        {row.timestamp}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

      </main>

        <footer className="bg-white border-t border-gray-200 px-6 py-3 flex flex-wrap items-center justify-between gap-2 text-[10px] text-gray-400">
        <span className="flex items-center gap-1.5 font-medium">
            <Shield size={11} className="text-blue-500" aria-hidden="true" />
          PhishGuard Intelligence Hub v2.4.1
        </span>
          <span className="flex items-center gap-1.5">
          <FileText size={11} aria-hidden="true" />
          Classification: Restricted · SOC-Internal
        </span>
        <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          Feed Status: Live
        </span>
      </footer>

    </div>
  );
}
