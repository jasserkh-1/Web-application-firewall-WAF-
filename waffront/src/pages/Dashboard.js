// WafDashboard.js
import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  BarChart,
  LineChart,
  PieChart,
  Bar,
  Line,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import Globe from "react-globe.gl";
import "../styles/Dashboard.css";
import { ArrowUpRight, Shield, AlertTriangle, Sun, Moon } from "lucide-react";

/* ───────────────────────────  icons (unchanged) ─────────────────────────── */
const ArrowUpRightIcon = () => <ArrowUpRight />;
const ShieldIcon = () => <Shield />;
const AlertTriangleIcon = () => <AlertTriangle />;
const ClockIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="10" />
    <polyline points="12 6 12 12 16 14" />
  </svg>
);
const FilterIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
  </svg>
);
const RefreshIcon = ({ spinning }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={spinning ? "spin" : ""}
  >
    <path d="M23 4v6h-6" />
    <path d="M1 20v-6h6" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
);
const SunIconComponent = () => <Sun />;
const MoonIconComponent = () => <Moon />;

/* ───────────────────────────  component ─────────────────────────── */
const WafDashboard = () => {
  /* ---------- theme toggle ---------- */
  const [darkMode, setDarkMode] = useState(
    localStorage.getItem("darkMode") === "enabled"
  );
  useEffect(() => {
    document.body.classList.toggle("dark-mode", darkMode);
  }, [darkMode]);
  const toggleDarkMode = () =>
    setDarkMode((m) => {
      const newVal = !m;
      localStorage.setItem("darkMode", newVal ? "enabled" : "disabled");
      return newVal;
    });

  /* ---------- backend data ---------- */
  const [dashboardData, setDashboardData] = useState(null); // null → loading
  const [fetchError, setFetchError] = useState(null);
  const [isFetching, setIsFetching] = useState(false);
  const [timeRange, setTimeRange] = useState("7d"); // UI filter only

  const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042", "#8884D8"];

  const fetchData = async () => {
    setIsFetching(true);
    setFetchError(null);
    try {
      // call both endpoints in parallel
      const [logsRes, statsRes] = await Promise.all([
        axios.get("http://127.0.0.1:5000/api/logs"),
        axios.get("http://127.0.0.1:5000/api/stats"),
      ]);

      const logs = logsRes.data; // array of objects
      const stats = statsRes.data.data; // {allowed_requests, blocked_requests, total_requests}

      /* ----- derive dashboard series ----- */
      // 1. attack types distribution
      const attackTypesMap = logs.reduce((acc, log) => {
        acc[log.attack_type] = (acc[log.attack_type] || 0) + 1;
        return acc;
      }, {});
      const attackTypes = Object.entries(attackTypesMap).map(([name, value]) => ({
        name,
        value,
      }));

      // 2. five most recent logs (already blocked)
      const recentAttacks = [...logs]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 5)
        .map((l, i) => ({
          id: i,
          timestamp: l.timestamp,
          ip: l.ip,
          type: l.attack_type,
          path: l.path || l.payload?.slice(0, 40) || "<unknown>",
          severity: l.severity || "Medium",
        }));

      // 3. traffic history by day
      const trafficMap = logs.reduce((acc, log) => {
        const day = new Date(log.timestamp).toISOString().split("T")[0];
        acc[day] = acc[day] || { total: 0, blocked: 0 };
        acc[day].blocked += 1; // every log here is a blocked request
        return acc;
      }, {});
      // fill total from stats proportionally (simple heuristic)
      Object.values(trafficMap).forEach(
        (v) => (v.total = v.blocked * (stats.total_requests / stats.blocked_requests))
      );
      const trafficHistory = Object.entries(trafficMap)
        .map(([date, { total, blocked }]) => ({ date, total, blocked }))
        .sort((a, b) => a.date.localeCompare(b.date));

      // 4. top blocked IPs
      const ipMap = logs.reduce((acc, log) => {
        acc[log.ip] = (acc[log.ip] || 0) + 1;
        return acc;
      }, {});
      const topBlockedIPs = Object.entries(ipMap)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      /* assemble everything the JSX expects */
      setDashboardData({
        totalRequests: stats.total_requests,
        blockedAttacks: stats.blocked_requests,
        attackTypes,
        recentAttacks,
        trafficHistory,
        topBlockedIPs,
      });
    } catch (err) {
      setFetchError(err.message || "Unknown error");
    } finally {
      setIsFetching(false);
    }
  };

  /* first load + 5-min interval refresh */
  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 300_000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeRange]);

  /* ---------- globe (static demo data) ---------- */
  const globeData = [
    { name: "China", lat: 35.86, lng: 104.19, attacks: 9876 },
    { name: "United States", lat: 37.09, lng: -95.71, attacks: 12345 },
    { name: "India", lat: 20.59, lng: 78.96, attacks: 3456 },
  ];
  const globeRef = useRef();
  useEffect(() => {
    if (globeRef.current) {
      globeRef.current.controls().autoRotate = true;
      globeRef.current.controls().autoRotateSpeed = 0.3;
    }
  }, []);
  const flyToCountry = (c) =>
    globeRef.current?.pointOfView({ lat: c.lat, lng: c.lng, altitude: 1.5 }, 1000);

  /* ---------- helpers ---------- */
  const formatTimestamp = (ts) =>
    new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  /* ---------- early return while loading ---------- */
  if (!dashboardData) return <p style={{ padding: "2rem" }}>Loading …</p>;
  if (fetchError) return <p style={{ padding: "2rem" }}>Error: {fetchError}</p>;

  /* ---------- JSX (unchanged layout) ---------- */
  return (
    <div className="dashboard-container">
      {/* header */}
      <header className="dashboard-header">
        <h1 className="dashboard-title">WAF Security Dashboard</h1>
        <div className="header-info-bar">
          <div className="last-updated">
            <ClockIcon />
            <span>Last updated: {new Date().toLocaleString()}</span>
          </div>
          <div className="filter-controls">
            <div className="filter-group">
              <FilterIcon />
              <select
                className="filter-select"
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
              >
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
              </select>
            </div>
            <button className="refresh-button" onClick={fetchData} disabled={isFetching}>
              <RefreshIcon spinning={isFetching} />
              <span>Refresh</span>
            </button>
            <button className="refresh-button" onClick={toggleDarkMode}>
              {darkMode ? <SunIconComponent /> : <MoonIconComponent />}
              <span>{darkMode ? "Light Mode" : "Dark Mode"}</span>
            </button>
          </div>
        </div>
      </header>

      {/* Stats cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-content">
            <div className="stat-icon stat-icon-requests">
              <ArrowUpRightIcon />
            </div>
            <div>
              <p className="stat-label">Total Requests</p>
              <h2 className="stat-value">
                {dashboardData.totalRequests.toLocaleString()}
              </h2>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-content">
            <div className="stat-icon stat-icon-blocked">
              <ShieldIcon />
            </div>
            <div>
              <p className="stat-label">Blocked Attacks</p>
              <h2 className="stat-value">
                {dashboardData.blockedAttacks.toLocaleString()}
              </h2>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-content">
            <div className="stat-icon stat-icon-rate">
              <AlertTriangleIcon />
            </div>
            <div>
              <p className="stat-label">Block Rate</p>
              <h2 className="stat-value">
                {(
                  (dashboardData.blockedAttacks / dashboardData.totalRequests) *
                  100
                ).toFixed(2)}
                %
              </h2>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="charts-grid">
        <div className="chart-card">
          <h3 className="chart-title">Traffic History</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={dashboardData.trafficHistory}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="total" stroke="#0088FE" name="Total" />
                <Line
                  type="monotone"
                  dataKey="blocked"
                  stroke="#FF8042"
                  name="Blocked"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-card">
          <h3 className="chart-title">Attack Types</h3>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={dashboardData.attackTypes}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) =>
                    `${name}: ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {dashboardData.attackTypes.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* recent attacks */}
      <div className="charts-grid">
        <div className="chart-card">
          <h3 className="chart-title">Recent Blocked Attacks</h3>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>IP</th>
                  <th>Type</th>
                  <th>payload</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {dashboardData.recentAttacks.map((a) => (
                  <tr key={a.id}>
                    <td>{formatTimestamp(a.timestamp)}</td>
                    <td>{a.ip}</td>
                    <td>{a.type}</td>
                    <td className="truncate">{a.path}</td>
                    <td>
                      <span
                        className={`severity-badge severity-${a.severity.toLowerCase()}`}
                      >
                        {a.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* globe + country list */}
      <div className="charts-grid">
        <div className="chart-card">
          <h3 className="chart-title">Global Attack Data</h3>
          <div className="globe-container">
            <Globe
              ref={globeRef}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              backgroundColor="rgba(0,0,0,0)"
              width={500}
              height={500}
              showGraticules
              atmosphereColor="#87CEEB"
              atmosphereAltitude={0.25}
              pointsData={globeData}
              pointLat="lat"
              pointLng="lng"
              pointRadius={0.3}
              pointColor={() => "rgba(0,255,255,0.8)"}
              pointLabel={(d) => `${d.name}\nAttacks: ${d.attacks.toLocaleString()}`}
            />
          </div>
        </div>
        <div className="chart-card">
          <h3 className="chart-title">Country Statistics</h3>
          <ul className="country-list">
            {globeData.map((c) => (
              <li key={c.name} onClick={() => flyToCountry(c)}>
                <span className="country-name">{c.name}</span>
                <span className="country-stats">
                  Attacks: {c.attacks.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default WafDashboard;
