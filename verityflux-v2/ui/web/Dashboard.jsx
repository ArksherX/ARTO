import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, XCircle, Clock, Activity,
  Eye, Bell, Settings, Search, Filter, ChevronRight, ChevronDown,
  Terminal, Zap, Lock, Unlock, RefreshCw, ExternalLink, Copy,
  BarChart3, TrendingUp, TrendingDown, Users, Bot, FileText,
  Play, Pause, Square, Layers, Database, Globe, Server,
  AlertCircle, Info, Check, X, MoreVertical, ArrowRight,
  Cpu, HardDrive, Wifi, WifiOff, Menu, LogOut, User,
  Sun, Moon, Maximize2, Minimize2, Download, Upload
} from 'lucide-react';

// =============================================================================
// DESIGN TOKENS & THEME
// =============================================================================

const theme = {
  colors: {
    // Core palette - Cyber security aesthetic with electric accents
    bg: {
      primary: '#0a0e17',
      secondary: '#111827',
      tertiary: '#1a2234',
      elevated: '#1f2937',
      card: 'rgba(17, 24, 39, 0.8)',
    },
    text: {
      primary: '#f3f4f6',
      secondary: '#9ca3af',
      muted: '#6b7280',
      inverse: '#0a0e17',
    },
    accent: {
      primary: '#00d4ff',      // Electric cyan
      secondary: '#7c3aed',    // Violet
      success: '#10b981',      // Emerald
      warning: '#f59e0b',      // Amber
      danger: '#ef4444',       // Red
      info: '#3b82f6',         // Blue
    },
    status: {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e',
      info: '#3b82f6',
    },
    border: {
      default: 'rgba(255, 255, 255, 0.06)',
      hover: 'rgba(255, 255, 255, 0.12)',
      focus: '#00d4ff',
    },
  },
  fonts: {
    display: "'JetBrains Mono', 'Fira Code', monospace",
    body: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
    mono: "'JetBrains Mono', 'Fira Code', monospace",
  },
  shadows: {
    sm: '0 1px 2px rgba(0, 0, 0, 0.4)',
    md: '0 4px 6px rgba(0, 0, 0, 0.4)',
    lg: '0 10px 15px rgba(0, 0, 0, 0.5)',
    glow: '0 0 20px rgba(0, 212, 255, 0.15)',
    glowStrong: '0 0 30px rgba(0, 212, 255, 0.3)',
  },
};

// =============================================================================
// MOCK DATA
// =============================================================================

const mockMetrics = {
  agents: { total: 12, healthy: 10, warning: 1, critical: 1 },
  events: { total: 15847, last24h: 1243, blocked: 89 },
  approvals: { pending: 7, approved: 234, denied: 45 },
  scans: { completed: 156, inProgress: 3, scheduled: 8 },
  riskScore: 34,
  threatLevel: 'elevated',
};

const mockAlerts = [
  { id: 'ALT-001', severity: 'critical', title: 'Prompt Injection Detected', agent: 'customer-support-bot', time: '2 min ago', status: 'new' },
  { id: 'ALT-002', severity: 'high', title: 'Excessive Tool Calls', agent: 'data-analyst-agent', time: '15 min ago', status: 'investigating' },
  { id: 'ALT-003', severity: 'medium', title: 'Unusual Query Pattern', agent: 'search-assistant', time: '1 hr ago', status: 'new' },
  { id: 'ALT-004', severity: 'low', title: 'Rate Limit Warning', agent: 'api-gateway-bot', time: '2 hr ago', status: 'acknowledged' },
  { id: 'ALT-005', severity: 'critical', title: 'Goal Hijacking Attempt', agent: 'task-automation-agent', time: '3 hr ago', status: 'resolved' },
];

const mockApprovals = [
  { id: 'APR-001', agent: 'finance-bot', tool: 'database_write', action: 'UPDATE accounts SET...', risk: 78, timeLeft: '12:45', status: 'pending' },
  { id: 'APR-002', agent: 'hr-assistant', tool: 'email_send', action: 'Send to all@company.com', risk: 65, timeLeft: '08:30', status: 'pending' },
  { id: 'APR-003', agent: 'devops-agent', tool: 'shell_exec', action: 'kubectl delete pod...', risk: 92, timeLeft: '05:15', status: 'pending' },
  { id: 'APR-004', agent: 'research-bot', tool: 'file_write', action: 'Write to /var/data/...', risk: 45, timeLeft: '18:00', status: 'pending' },
];

const mockAgents = [
  { id: 'AGT-001', name: 'customer-support-bot', type: 'LangChain', status: 'healthy', requests: 4521, blocked: 23, risk: 15, lastSeen: '10s ago' },
  { id: 'AGT-002', name: 'data-analyst-agent', type: 'AutoGen', status: 'warning', requests: 2341, blocked: 156, risk: 45, lastSeen: '2m ago' },
  { id: 'AGT-003', name: 'task-automation-agent', type: 'CrewAI', status: 'critical', requests: 892, blocked: 89, risk: 78, lastSeen: '5m ago' },
  { id: 'AGT-004', name: 'search-assistant', type: 'Custom', status: 'healthy', requests: 8723, blocked: 12, risk: 8, lastSeen: '5s ago' },
  { id: 'AGT-005', name: 'finance-bot', type: 'LangChain', status: 'healthy', requests: 1234, blocked: 3, risk: 22, lastSeen: '30s ago' },
];

const mockEvents = [
  { time: '14:32:15', agent: 'customer-support-bot', event: 'Tool Call', tool: 'web_search', decision: 'allow', risk: 12 },
  { time: '14:32:14', agent: 'data-analyst-agent', event: 'Prompt', tool: '-', decision: 'allow', risk: 8 },
  { time: '14:32:12', agent: 'task-automation-agent', event: 'Tool Call', tool: 'file_read', decision: 'block', risk: 85 },
  { time: '14:32:10', agent: 'finance-bot', event: 'Tool Call', tool: 'database_query', decision: 'review', risk: 67 },
  { time: '14:32:08', agent: 'search-assistant', event: 'Response', tool: '-', decision: 'allow', risk: 5 },
];

const mockIncidents = [
  { id: 'INC-2025-00042', title: 'Mass Prompt Injection Campaign', priority: 'P1', status: 'active', affected: 3, created: '2 hours ago' },
  { id: 'INC-2025-00041', title: 'Data Exfiltration Attempt', priority: 'P2', status: 'investigating', affected: 1, created: '5 hours ago' },
  { id: 'INC-2025-00040', title: 'Unauthorized API Access', priority: 'P3', status: 'resolved', affected: 2, created: '1 day ago' },
];

// =============================================================================
// UTILITY COMPONENTS
// =============================================================================

const Badge = ({ variant = 'default', children, pulse = false, className = '' }) => {
  const variants = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border-green-500/30',
    info: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    success: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    warning: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    danger: 'bg-red-500/20 text-red-400 border-red-500/30',
    default: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    accent: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  };
  
  return (
    <span className={`
      inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full border
      ${variants[variant] || variants.default}
      ${pulse ? 'animate-pulse' : ''}
      ${className}
    `}>
      {pulse && <span className="w-1.5 h-1.5 rounded-full bg-current animate-ping" />}
      {children}
    </span>
  );
};

const Card = ({ children, className = '', hover = false, glow = false }) => (
  <div className={`
    rounded-xl border border-white/[0.06] bg-gradient-to-b from-gray-900/80 to-gray-900/40
    backdrop-blur-xl
    ${hover ? 'hover:border-white/[0.12] hover:bg-gray-800/50 transition-all duration-300 cursor-pointer' : ''}
    ${glow ? 'shadow-[0_0_30px_rgba(0,212,255,0.1)]' : ''}
    ${className}
  `}>
    {children}
  </div>
);

const Button = ({ children, variant = 'default', size = 'md', className = '', ...props }) => {
  const variants = {
    default: 'bg-gray-800 hover:bg-gray-700 text-gray-200 border-gray-700',
    primary: 'bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border-cyan-500/30',
    success: 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border-emerald-500/30',
    danger: 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border-red-500/30',
    ghost: 'bg-transparent hover:bg-white/5 text-gray-400 hover:text-gray-200 border-transparent',
  };
  
  const sizes = {
    sm: 'px-2.5 py-1.5 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
  };
  
  return (
    <button
      className={`
        inline-flex items-center justify-center gap-2 font-medium rounded-lg border
        transition-all duration-200 active:scale-95
        ${variants[variant]}
        ${sizes[size]}
        ${className}
      `}
      {...props}
    >
      {children}
    </button>
  );
};

const IconButton = ({ icon: Icon, variant = 'ghost', className = '', ...props }) => (
  <button
    className={`
      p-2 rounded-lg transition-all duration-200 active:scale-95
      ${variant === 'ghost' ? 'hover:bg-white/5 text-gray-400 hover:text-gray-200' : ''}
      ${variant === 'danger' ? 'hover:bg-red-500/20 text-gray-400 hover:text-red-400' : ''}
      ${className}
    `}
    {...props}
  >
    <Icon className="w-5 h-5" />
  </button>
);

const ProgressBar = ({ value, max = 100, variant = 'default', size = 'md', showLabel = false }) => {
  const percent = Math.min(100, Math.max(0, (value / max) * 100));
  
  const variants = {
    default: 'bg-cyan-500',
    success: 'bg-emerald-500',
    warning: 'bg-amber-500',
    danger: 'bg-red-500',
    gradient: 'bg-gradient-to-r from-cyan-500 to-violet-500',
  };
  
  const sizes = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
  };
  
  return (
    <div className="w-full">
      <div className={`w-full bg-gray-800 rounded-full overflow-hidden ${sizes[size]}`}>
        <div 
          className={`${sizes[size]} ${variants[variant]} rounded-full transition-all duration-500 ease-out`}
          style={{ width: `${percent}%` }}
        />
      </div>
      {showLabel && (
        <span className="text-xs text-gray-500 mt-1">{Math.round(percent)}%</span>
      )}
    </div>
  );
};

const Sparkline = ({ data, color = '#00d4ff', height = 40 }) => {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  
  const points = data.map((value, i) => {
    const x = (i / (data.length - 1)) * 100;
    const y = height - ((value - min) / range) * height;
    return `${x},${y}`;
  }).join(' ');
  
  return (
    <svg width="100%" height={height} className="overflow-visible">
      <defs>
        <linearGradient id={`sparkline-gradient-${color}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <polygon
        points={`0,${height} ${points} 100,${height}`}
        fill={`url(#sparkline-gradient-${color})`}
      />
    </svg>
  );
};

// =============================================================================
// METRIC CARD COMPONENT
// =============================================================================

const MetricCard = ({ icon: Icon, label, value, subValue, trend, color = 'cyan', sparkData }) => (
  <Card className="p-4" hover>
    <div className="flex items-start justify-between">
      <div className={`p-2.5 rounded-lg bg-${color}-500/10`}>
        <Icon className={`w-5 h-5 text-${color}-400`} />
      </div>
      {trend && (
        <div className={`flex items-center gap-1 text-xs ${trend > 0 ? 'text-emerald-400' : 'text-red-400'}`}>
          {trend > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          {Math.abs(trend)}%
        </div>
      )}
    </div>
    <div className="mt-3">
      <div className="text-2xl font-bold text-white font-mono">{value}</div>
      <div className="text-sm text-gray-500">{label}</div>
      {subValue && <div className="text-xs text-gray-600 mt-1">{subValue}</div>}
    </div>
    {sparkData && (
      <div className="mt-3">
        <Sparkline data={sparkData} color={`var(--color-${color})`} height={30} />
      </div>
    )}
  </Card>
);

// =============================================================================
// SIDEBAR COMPONENT
// =============================================================================

const Sidebar = ({ activeView, setActiveView, collapsed, setCollapsed }) => {
  const navItems = [
    { id: 'dashboard', icon: BarChart3, label: 'Dashboard' },
    { id: 'agents', icon: Bot, label: 'Agents' },
    { id: 'approvals', icon: Shield, label: 'Approvals', badge: 7 },
    { id: 'alerts', icon: Bell, label: 'Alerts', badge: 3 },
    { id: 'incidents', icon: AlertTriangle, label: 'Incidents' },
    { id: 'scans', icon: Search, label: 'Scans' },
    { id: 'events', icon: Activity, label: 'Event Log' },
    { id: 'vulnerabilities', icon: Database, label: 'Vuln DB' },
  ];
  
  const bottomItems = [
    { id: 'settings', icon: Settings, label: 'Settings' },
  ];
  
  return (
    <aside className={`
      fixed left-0 top-0 h-screen bg-gray-950/80 backdrop-blur-xl border-r border-white/[0.06]
      transition-all duration-300 z-50 flex flex-col
      ${collapsed ? 'w-16' : 'w-64'}
    `}>
      {/* Logo */}
      <div className="h-16 flex items-center px-4 border-b border-white/[0.06]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {!collapsed && (
            <div>
              <div className="font-bold text-white text-lg tracking-tight">VerityFlux</div>
              <div className="text-[10px] text-cyan-400 uppercase tracking-wider">Enterprise</div>
            </div>
          )}
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 py-4 overflow-y-auto">
        <div className="px-3 space-y-1">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id)}
              className={`
                w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                transition-all duration-200 group relative
                ${activeView === item.id 
                  ? 'bg-cyan-500/10 text-cyan-400' 
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                }
              `}
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {!collapsed && (
                <>
                  <span className="flex-1 text-left">{item.label}</span>
                  {item.badge && (
                    <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-red-500/20 text-red-400">
                      {item.badge}
                    </span>
                  )}
                </>
              )}
              {collapsed && item.badge && (
                <span className="absolute -top-1 -right-1 w-4 h-4 text-[10px] font-bold rounded-full bg-red-500 text-white flex items-center justify-center">
                  {item.badge}
                </span>
              )}
              {activeView === item.id && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-cyan-400 rounded-r" />
              )}
            </button>
          ))}
        </div>
      </nav>
      
      {/* Bottom */}
      <div className="p-3 border-t border-white/[0.06]">
        {bottomItems.map(item => (
          <button
            key={item.id}
            onClick={() => setActiveView(item.id)}
            className={`
              w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
              transition-all duration-200
              ${activeView === item.id 
                ? 'bg-cyan-500/10 text-cyan-400' 
                : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }
            `}
          >
            <item.icon className="w-5 h-5" />
            {!collapsed && <span>{item.label}</span>}
          </button>
        ))}
        
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-gray-400 hover:text-gray-200 hover:bg-white/5 mt-1"
        >
          {collapsed ? <Maximize2 className="w-5 h-5" /> : <Minimize2 className="w-5 h-5" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
};

// =============================================================================
// HEADER COMPONENT
// =============================================================================

const Header = ({ threatLevel }) => {
  const [searchFocused, setSearchFocused] = useState(false);
  
  const threatColors = {
    low: 'text-emerald-400 bg-emerald-500/10',
    elevated: 'text-yellow-400 bg-yellow-500/10',
    high: 'text-orange-400 bg-orange-500/10',
    critical: 'text-red-400 bg-red-500/10 animate-pulse',
  };
  
  return (
    <header className="h-16 border-b border-white/[0.06] bg-gray-950/50 backdrop-blur-xl flex items-center justify-between px-6">
      <div className="flex items-center gap-4 flex-1">
        {/* Search */}
        <div className={`
          relative flex items-center transition-all duration-300
          ${searchFocused ? 'w-96' : 'w-72'}
        `}>
          <Search className="absolute left-3 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search agents, events, vulnerabilities..."
            className="w-full pl-10 pr-4 py-2 bg-gray-900/50 border border-white/[0.06] rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20"
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
          />
          <kbd className="absolute right-3 px-1.5 py-0.5 text-[10px] font-medium text-gray-500 bg-gray-800 rounded border border-gray-700">⌘K</kbd>
        </div>
      </div>
      
      <div className="flex items-center gap-3">
        {/* Threat Level Indicator */}
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ${threatColors[threatLevel]}`}>
          <div className="w-2 h-2 rounded-full bg-current" />
          <span className="text-sm font-medium uppercase tracking-wider">
            {threatLevel} Threat
          </span>
        </div>
        
        {/* Status Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 rounded-lg">
          <Wifi className="w-4 h-4 text-emerald-400" />
          <span className="text-sm text-emerald-400">Connected</span>
        </div>
        
        {/* Notifications */}
        <IconButton icon={Bell} className="relative">
          <span className="absolute -top-1 -right-1 w-4 h-4 text-[10px] font-bold rounded-full bg-red-500 text-white flex items-center justify-center">
            3
          </span>
        </IconButton>
        
        {/* User Menu */}
        <button className="flex items-center gap-2 pl-3 pr-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-cyan-500 flex items-center justify-center text-white font-bold text-sm">
            A
          </div>
          <ChevronDown className="w-4 h-4 text-gray-400" />
        </button>
      </div>
    </header>
  );
};

// =============================================================================
// DASHBOARD VIEW
// =============================================================================

const DashboardView = () => {
  const [timeRange, setTimeRange] = useState('24h');
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Overview</h1>
          <p className="text-gray-500 text-sm mt-1">Real-time monitoring and threat assessment</p>
        </div>
        <div className="flex items-center gap-2">
          {['1h', '24h', '7d', '30d'].map(range => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-3 py-1.5 text-sm rounded-lg transition-all ${
                timeRange === range 
                  ? 'bg-cyan-500/20 text-cyan-400' 
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`}
            >
              {range}
            </button>
          ))}
          <Button variant="primary" size="sm">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
        </div>
      </div>
      
      {/* Metrics Grid */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard 
          icon={Bot} 
          label="Active Agents" 
          value={mockMetrics.agents.total}
          subValue={`${mockMetrics.agents.healthy} healthy, ${mockMetrics.agents.warning} warning`}
          color="cyan"
          trend={5}
          sparkData={[4, 5, 6, 8, 7, 9, 10, 11, 12, 12]}
        />
        <MetricCard 
          icon={Activity} 
          label="Events (24h)" 
          value={mockMetrics.events.last24h.toLocaleString()}
          subValue={`${mockMetrics.events.blocked} blocked`}
          color="violet"
          trend={12}
          sparkData={[120, 145, 130, 160, 155, 180, 165, 190, 185, 200]}
        />
        <MetricCard 
          icon={Shield} 
          label="Pending Approvals" 
          value={mockMetrics.approvals.pending}
          subValue="7 require immediate attention"
          color="amber"
        />
        <MetricCard 
          icon={Search} 
          label="Security Scans" 
          value={mockMetrics.scans.completed}
          subValue={`${mockMetrics.scans.inProgress} in progress`}
          color="emerald"
          trend={-3}
        />
      </div>
      
      {/* Risk Score & Alerts */}
      <div className="grid grid-cols-3 gap-6">
        {/* Risk Score */}
        <Card className="p-6" glow>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Organization Risk Score</h3>
            <Badge variant="medium">Moderate</Badge>
          </div>
          <div className="flex items-center gap-6">
            <div className="relative w-32 h-32">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  fill="none"
                  stroke="rgba(255,255,255,0.1)"
                  strokeWidth="12"
                />
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  fill="none"
                  stroke="url(#riskGradient)"
                  strokeWidth="12"
                  strokeLinecap="round"
                  strokeDasharray={`${mockMetrics.riskScore * 3.52} 352`}
                />
                <defs>
                  <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#10b981" />
                    <stop offset="50%" stopColor="#f59e0b" />
                    <stop offset="100%" stopColor="#ef4444" />
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-3xl font-bold text-white font-mono">{mockMetrics.riskScore}</div>
                  <div className="text-xs text-gray-500">/ 100</div>
                </div>
              </div>
            </div>
            <div className="flex-1 space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Critical Findings</span>
                <span className="text-red-400 font-mono">2</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">High Findings</span>
                <span className="text-orange-400 font-mono">5</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Medium Findings</span>
                <span className="text-yellow-400 font-mono">12</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Low Findings</span>
                <span className="text-emerald-400 font-mono">28</span>
              </div>
            </div>
          </div>
        </Card>
        
        {/* Recent Alerts */}
        <Card className="p-6 col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Recent Alerts</h3>
            <Button variant="ghost" size="sm">
              View All <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
          <div className="space-y-3">
            {mockAlerts.slice(0, 4).map(alert => (
              <div key={alert.id} className="flex items-center gap-4 p-3 rounded-lg bg-gray-900/50 hover:bg-gray-800/50 transition-colors cursor-pointer group">
                <div className={`w-2 h-2 rounded-full ${
                  alert.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                  alert.severity === 'high' ? 'bg-orange-500' :
                  alert.severity === 'medium' ? 'bg-yellow-500' : 'bg-emerald-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white truncate">{alert.title}</div>
                  <div className="text-sm text-gray-500">{alert.agent}</div>
                </div>
                <Badge variant={alert.severity}>{alert.severity}</Badge>
                <span className="text-xs text-gray-500">{alert.time}</span>
                <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-gray-400 transition-colors" />
              </div>
            ))}
          </div>
        </Card>
      </div>
      
      {/* Bottom Grid */}
      <div className="grid grid-cols-2 gap-6">
        {/* Pending Approvals */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Pending Approvals</h3>
            <Badge variant="warning" pulse>{mockApprovals.length} pending</Badge>
          </div>
          <div className="space-y-3">
            {mockApprovals.slice(0, 3).map(approval => (
              <div key={approval.id} className="p-4 rounded-lg border border-white/[0.06] bg-gray-900/30">
                <div className="flex items-center justify-between mb-2">
                  <div className="font-medium text-white">{approval.agent}</div>
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-gray-500" />
                    <span className="text-sm font-mono text-amber-400">{approval.timeLeft}</span>
                  </div>
                </div>
                <div className="text-sm text-gray-400 mb-3 font-mono truncate">{approval.tool}: {approval.action}</div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500">Risk Score:</span>
                    <span className={`text-sm font-bold ${
                      approval.risk >= 80 ? 'text-red-400' :
                      approval.risk >= 60 ? 'text-orange-400' :
                      approval.risk >= 40 ? 'text-yellow-400' : 'text-emerald-400'
                    }`}>{approval.risk}%</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="success" size="sm">
                      <Check className="w-4 h-4" />
                      Approve
                    </Button>
                    <Button variant="danger" size="sm">
                      <X className="w-4 h-4" />
                      Deny
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
        
        {/* Active Incidents */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Active Incidents</h3>
            <Button variant="primary" size="sm">
              <AlertTriangle className="w-4 h-4" />
              Create Incident
            </Button>
          </div>
          <div className="space-y-3">
            {mockIncidents.map(incident => (
              <div key={incident.id} className="p-4 rounded-lg border border-white/[0.06] bg-gray-900/30 hover:bg-gray-800/30 transition-colors cursor-pointer">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Badge variant={incident.priority === 'P1' ? 'critical' : incident.priority === 'P2' ? 'high' : 'medium'}>
                      {incident.priority}
                    </Badge>
                    <span className="text-sm font-mono text-gray-500">{incident.id}</span>
                  </div>
                  <Badge variant={incident.status === 'active' ? 'danger' : incident.status === 'investigating' ? 'warning' : 'success'}>
                    {incident.status}
                  </Badge>
                </div>
                <div className="font-medium text-white">{incident.title}</div>
                <div className="flex items-center justify-between mt-2 text-sm text-gray-500">
                  <span>{incident.affected} agents affected</span>
                  <span>{incident.created}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};

// =============================================================================
// AGENTS VIEW
// =============================================================================

const AgentsView = () => {
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [filter, setFilter] = useState('all');
  
  const filteredAgents = filter === 'all' 
    ? mockAgents 
    : mockAgents.filter(a => a.status === filter);
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">AI Agents</h1>
          <p className="text-gray-500 text-sm mt-1">Monitor and manage registered agents</p>
        </div>
        <Button variant="primary">
          <Bot className="w-4 h-4" />
          Register Agent
        </Button>
      </div>
      
      {/* Filter Tabs */}
      <div className="flex items-center gap-2 p-1 bg-gray-900/50 rounded-lg w-fit">
        {[
          { id: 'all', label: 'All Agents', count: mockAgents.length },
          { id: 'healthy', label: 'Healthy', count: mockAgents.filter(a => a.status === 'healthy').length },
          { id: 'warning', label: 'Warning', count: mockAgents.filter(a => a.status === 'warning').length },
          { id: 'critical', label: 'Critical', count: mockAgents.filter(a => a.status === 'critical').length },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setFilter(tab.id)}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-all ${
              filter === tab.id
                ? 'bg-gray-800 text-white shadow-lg'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab.label}
            <span className={`ml-2 px-1.5 py-0.5 text-xs rounded-full ${
              filter === tab.id ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-700 text-gray-400'
            }`}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>
      
      {/* Agents Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Agent</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Type</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Requests</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Blocked</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Risk</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Last Seen</th>
                <th className="text-right py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {filteredAgents.map(agent => (
                <tr 
                  key={agent.id} 
                  className="hover:bg-white/[0.02] transition-colors cursor-pointer"
                  onClick={() => setSelectedAgent(agent)}
                >
                  <td className="py-4 px-6">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                        agent.status === 'healthy' ? 'bg-emerald-500/10' :
                        agent.status === 'warning' ? 'bg-amber-500/10' : 'bg-red-500/10'
                      }`}>
                        <Bot className={`w-5 h-5 ${
                          agent.status === 'healthy' ? 'text-emerald-400' :
                          agent.status === 'warning' ? 'text-amber-400' : 'text-red-400'
                        }`} />
                      </div>
                      <div>
                        <div className="font-medium text-white">{agent.name}</div>
                        <div className="text-sm text-gray-500 font-mono">{agent.id}</div>
                      </div>
                    </div>
                  </td>
                  <td className="py-4 px-6">
                    <Badge variant="info">{agent.type}</Badge>
                  </td>
                  <td className="py-4 px-6">
                    <Badge variant={agent.status === 'healthy' ? 'success' : agent.status === 'warning' ? 'warning' : 'danger'}>
                      {agent.status}
                    </Badge>
                  </td>
                  <td className="py-4 px-6 font-mono text-white">{agent.requests.toLocaleString()}</td>
                  <td className="py-4 px-6 font-mono text-red-400">{agent.blocked}</td>
                  <td className="py-4 px-6">
                    <div className="flex items-center gap-2">
                      <div className="w-16">
                        <ProgressBar 
                          value={agent.risk} 
                          variant={agent.risk >= 60 ? 'danger' : agent.risk >= 40 ? 'warning' : 'success'}
                          size="sm"
                        />
                      </div>
                      <span className="text-sm font-mono text-gray-400">{agent.risk}%</span>
                    </div>
                  </td>
                  <td className="py-4 px-6 text-sm text-gray-400">{agent.lastSeen}</td>
                  <td className="py-4 px-6 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <IconButton icon={Eye} />
                      <IconButton icon={Settings} />
                      <IconButton icon={MoreVertical} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

// =============================================================================
// APPROVALS VIEW
// =============================================================================

const ApprovalsView = () => {
  const [selectedApproval, setSelectedApproval] = useState(null);
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Approval Queue</h1>
          <p className="text-gray-500 text-sm mt-1">Human-in-the-loop decisions for high-risk actions</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="warning" pulse>{mockApprovals.length} pending</Badge>
          <Button variant="ghost" size="sm">
            <Settings className="w-4 h-4" />
            Policies
          </Button>
        </div>
      </div>
      
      {/* Approval Cards */}
      <div className="grid grid-cols-2 gap-4">
        {mockApprovals.map(approval => (
          <Card 
            key={approval.id} 
            className="p-6" 
            hover
            glow={approval.risk >= 80}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                  approval.risk >= 80 ? 'bg-red-500/10' :
                  approval.risk >= 60 ? 'bg-orange-500/10' :
                  approval.risk >= 40 ? 'bg-yellow-500/10' : 'bg-emerald-500/10'
                }`}>
                  <Shield className={`w-6 h-6 ${
                    approval.risk >= 80 ? 'text-red-400' :
                    approval.risk >= 60 ? 'text-orange-400' :
                    approval.risk >= 40 ? 'text-yellow-400' : 'text-emerald-400'
                  }`} />
                </div>
                <div>
                  <div className="font-semibold text-white">{approval.agent}</div>
                  <div className="text-sm text-gray-500">{approval.id}</div>
                </div>
              </div>
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-800">
                <Clock className="w-4 h-4 text-amber-400" />
                <span className="font-mono text-amber-400">{approval.timeLeft}</span>
              </div>
            </div>
            
            <div className="space-y-3 mb-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-500">Tool:</span>
                <code className="px-2 py-1 bg-gray-800 rounded text-sm text-cyan-400">{approval.tool}</code>
              </div>
              <div>
                <span className="text-sm text-gray-500">Action:</span>
                <code className="block mt-1 p-3 bg-gray-900 rounded-lg text-sm text-gray-300 font-mono overflow-x-auto">
                  {approval.action}
                </code>
              </div>
            </div>
            
            <div className="flex items-center justify-between mb-4">
              <div>
                <span className="text-sm text-gray-500">Risk Score</span>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-32">
                    <ProgressBar 
                      value={approval.risk} 
                      variant={approval.risk >= 80 ? 'danger' : approval.risk >= 60 ? 'warning' : 'success'}
                    />
                  </div>
                  <span className={`text-lg font-bold font-mono ${
                    approval.risk >= 80 ? 'text-red-400' :
                    approval.risk >= 60 ? 'text-orange-400' : 'text-yellow-400'
                  }`}>{approval.risk}%</span>
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Button variant="success" className="flex-1">
                <Check className="w-4 h-4" />
                Approve
              </Button>
              <Button variant="danger" className="flex-1">
                <X className="w-4 h-4" />
                Deny
              </Button>
              <Button variant="ghost">
                <MoreVertical className="w-4 h-4" />
              </Button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};

// =============================================================================
// EVENT LOG VIEW
// =============================================================================

const EventLogView = () => {
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState('all');
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Event Log</h1>
          <p className="text-gray-500 text-sm mt-1">Real-time security event stream</p>
        </div>
        <div className="flex items-center gap-2">
          <Button 
            variant={autoScroll ? 'primary' : 'ghost'} 
            size="sm"
            onClick={() => setAutoScroll(!autoScroll)}
          >
            {autoScroll ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            {autoScroll ? 'Live' : 'Paused'}
          </Button>
          <Button variant="ghost" size="sm">
            <Download className="w-4 h-4" />
            Export
          </Button>
        </div>
      </div>
      
      {/* Event Stream */}
      <Card className="overflow-hidden">
        <div className="p-4 border-b border-white/[0.06] bg-gray-900/50">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-500" />
              <span className="text-sm text-gray-400">Filter:</span>
            </div>
            {['all', 'allow', 'block', 'review'].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 text-sm rounded-md transition-colors ${
                  filter === f ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
        
        <div className="font-mono text-sm divide-y divide-white/[0.04]">
          {mockEvents.map((event, idx) => (
            <div key={idx} className="flex items-center gap-4 px-4 py-3 hover:bg-white/[0.02] transition-colors">
              <span className="text-gray-600 w-20">{event.time}</span>
              <span className={`w-16 ${
                event.decision === 'allow' ? 'text-emerald-400' :
                event.decision === 'block' ? 'text-red-400' : 'text-amber-400'
              }`}>{event.decision.toUpperCase()}</span>
              <span className="text-gray-400 w-40 truncate">{event.agent}</span>
              <span className="text-gray-500 w-24">{event.event}</span>
              <span className="text-cyan-400 w-32">{event.tool || '-'}</span>
              <span className={`w-12 text-right ${
                event.risk >= 60 ? 'text-red-400' :
                event.risk >= 40 ? 'text-amber-400' : 'text-gray-400'
              }`}>{event.risk}%</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

// =============================================================================
// VULNERABILITIES VIEW
// =============================================================================

const VulnerabilitiesView = () => {
  const vulns = [
    { id: 'LLM01', title: 'Prompt Injection', severity: 'critical', cvss: 9.8, source: 'OWASP LLM', tests: 15, findings: 2 },
    { id: 'LLM02', title: 'Sensitive Information Disclosure', severity: 'high', cvss: 8.5, source: 'OWASP LLM', tests: 12, findings: 1 },
    { id: 'LLM06', title: 'Excessive Agency', severity: 'critical', cvss: 9.0, source: 'OWASP LLM', tests: 18, findings: 3 },
    { id: 'ASI01', title: 'Agent Goal Hijacking', severity: 'critical', cvss: 9.9, source: 'OWASP Agentic', tests: 20, findings: 1 },
    { id: 'ASI02', title: 'Tool Misuse', severity: 'critical', cvss: 9.5, source: 'OWASP Agentic', tests: 16, findings: 2 },
    { id: 'ASI05', title: 'Unexpected Code Execution', severity: 'critical', cvss: 9.8, source: 'OWASP Agentic', tests: 14, findings: 0 },
  ];
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Vulnerability Database</h1>
          <p className="text-gray-500 text-sm mt-1">OWASP LLM Top 10 + Agentic Top 10 vulnerabilities</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="info">20 vulnerabilities</Badge>
          <Button variant="ghost" size="sm">
            <Upload className="w-4 h-4" />
            Import Update
          </Button>
        </div>
      </div>
      
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">ID</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Vulnerability</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">CVSS</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Source</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Tests</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {vulns.map(vuln => (
                <tr key={vuln.id} className="hover:bg-white/[0.02] transition-colors cursor-pointer">
                  <td className="py-4 px-6 font-mono text-cyan-400">{vuln.id}</td>
                  <td className="py-4 px-6 font-medium text-white">{vuln.title}</td>
                  <td className="py-4 px-6">
                    <Badge variant={vuln.severity}>{vuln.severity}</Badge>
                  </td>
                  <td className="py-4 px-6 font-mono text-white">{vuln.cvss}</td>
                  <td className="py-4 px-6 text-gray-400">{vuln.source}</td>
                  <td className="py-4 px-6 font-mono text-gray-400">{vuln.tests}</td>
                  <td className="py-4 px-6">
                    {vuln.findings > 0 ? (
                      <Badge variant="danger">{vuln.findings}</Badge>
                    ) : (
                      <Badge variant="success">0</Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

// =============================================================================
// ALERTS VIEW
// =============================================================================

const AlertsView = () => {
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [filter, setFilter] = useState('all');
  
  const alerts = [
    ...mockAlerts,
    { id: 'ALT-006', severity: 'high', title: 'Data Exfiltration Pattern', agent: 'research-bot', time: '4 hr ago', status: 'new' },
    { id: 'ALT-007', severity: 'medium', title: 'Anomalous API Usage', agent: 'integration-agent', time: '5 hr ago', status: 'investigating' },
    { id: 'ALT-008', severity: 'critical', title: 'System Prompt Leak Attempt', agent: 'chat-assistant', time: '6 hr ago', status: 'resolved' },
  ];
  
  const filteredAlerts = filter === 'all' 
    ? alerts 
    : alerts.filter(a => a.status === filter || a.severity === filter);
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
          <p className="text-gray-500 text-sm mt-1">Monitor and respond to security incidents</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm">
            <Filter className="w-4 h-4" />
            Filters
          </Button>
          <Button variant="primary" size="sm">
            <Bell className="w-4 h-4" />
            Alert Rules
          </Button>
        </div>
      </div>
      
      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">Critical</div>
            <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse" />
          </div>
          <div className="text-2xl font-bold text-red-400 font-mono mt-1">
            {alerts.filter(a => a.severity === 'critical').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">High</div>
            <div className="w-3 h-3 rounded-full bg-orange-500" />
          </div>
          <div className="text-2xl font-bold text-orange-400 font-mono mt-1">
            {alerts.filter(a => a.severity === 'high').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">Medium</div>
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
          </div>
          <div className="text-2xl font-bold text-yellow-400 font-mono mt-1">
            {alerts.filter(a => a.severity === 'medium').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">Low</div>
            <div className="w-3 h-3 rounded-full bg-emerald-500" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
            {alerts.filter(a => a.severity === 'low').length}
          </div>
        </Card>
      </div>
      
      {/* Filter Tabs */}
      <div className="flex items-center gap-2 p-1 bg-gray-900/50 rounded-lg w-fit">
        {['all', 'new', 'investigating', 'resolved'].map(tab => (
          <button
            key={tab}
            onClick={() => setFilter(tab)}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-all ${
              filter === tab
                ? 'bg-gray-800 text-white shadow-lg'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>
      
      {/* Alerts List */}
      <div className="space-y-3">
        {filteredAlerts.map(alert => (
          <Card 
            key={alert.id} 
            className="p-4" 
            hover
            glow={alert.severity === 'critical' && alert.status === 'new'}
          >
            <div className="flex items-center gap-4">
              <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                alert.severity === 'critical' ? 'bg-red-500/10' :
                alert.severity === 'high' ? 'bg-orange-500/10' :
                alert.severity === 'medium' ? 'bg-yellow-500/10' : 'bg-emerald-500/10'
              }`}>
                <AlertTriangle className={`w-6 h-6 ${
                  alert.severity === 'critical' ? 'text-red-400' :
                  alert.severity === 'high' ? 'text-orange-400' :
                  alert.severity === 'medium' ? 'text-yellow-400' : 'text-emerald-400'
                }`} />
              </div>
              
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-gray-500">{alert.id}</span>
                  <Badge variant={alert.severity}>{alert.severity}</Badge>
                  <Badge variant={
                    alert.status === 'new' ? 'info' : 
                    alert.status === 'investigating' ? 'warning' : 'success'
                  }>{alert.status}</Badge>
                </div>
                <div className="font-semibold text-white mt-1">{alert.title}</div>
                <div className="text-sm text-gray-500 mt-0.5">
                  Agent: <span className="text-cyan-400">{alert.agent}</span> · {alert.time}
                </div>
              </div>
              
              <div className="flex items-center gap-2">
                <Button variant="ghost" size="sm">
                  <Eye className="w-4 h-4" />
                  View
                </Button>
                {alert.status !== 'resolved' && (
                  <Button variant="primary" size="sm">
                    <Check className="w-4 h-4" />
                    Acknowledge
                  </Button>
                )}
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};

// =============================================================================
// INCIDENTS VIEW
// =============================================================================

const IncidentsView = () => {
  const [showCreate, setShowCreate] = useState(false);
  
  const incidents = [
    ...mockIncidents,
    { id: 'INC-2025-00039', title: 'Coordinated Prompt Attack', priority: 'P1', status: 'resolved', affected: 5, created: '2 days ago' },
    { id: 'INC-2025-00038', title: 'Model Jailbreak Attempt', priority: 'P2', status: 'resolved', affected: 1, created: '3 days ago' },
  ];
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Incident Management</h1>
          <p className="text-gray-500 text-sm mt-1">Track and manage security incidents</p>
        </div>
        <Button variant="primary" onClick={() => setShowCreate(true)}>
          <AlertTriangle className="w-4 h-4" />
          Create Incident
        </Button>
      </div>
      
      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="text-sm text-gray-500">Active</div>
          <div className="text-2xl font-bold text-red-400 font-mono mt-1">
            {incidents.filter(i => i.status === 'active').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-gray-500">Investigating</div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">
            {incidents.filter(i => i.status === 'investigating').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-gray-500">Resolved (30d)</div>
          <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
            {incidents.filter(i => i.status === 'resolved').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-gray-500">MTTR</div>
          <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">4.2h</div>
        </Card>
      </div>
      
      {/* Incidents Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Incident</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Title</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Priority</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Affected</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Created</th>
                <th className="text-right py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {incidents.map(incident => (
                <tr key={incident.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-4 px-6 font-mono text-cyan-400">{incident.id}</td>
                  <td className="py-4 px-6 font-medium text-white">{incident.title}</td>
                  <td className="py-4 px-6">
                    <Badge variant={
                      incident.priority === 'P1' ? 'critical' : 
                      incident.priority === 'P2' ? 'high' : 'medium'
                    }>{incident.priority}</Badge>
                  </td>
                  <td className="py-4 px-6">
                    <Badge variant={
                      incident.status === 'active' ? 'danger' :
                      incident.status === 'investigating' ? 'warning' : 'success'
                    }>{incident.status}</Badge>
                  </td>
                  <td className="py-4 px-6 text-gray-400">{incident.affected} agents</td>
                  <td className="py-4 px-6 text-gray-500">{incident.created}</td>
                  <td className="py-4 px-6 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <IconButton icon={Eye} />
                      <IconButton icon={FileText} />
                      <IconButton icon={MoreVertical} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

// =============================================================================
// SCANS VIEW
// =============================================================================

const ScansView = () => {
  const [showNewScan, setShowNewScan] = useState(false);
  
  const scans = [
    { id: 'SCN-001', target: 'customer-support-bot', profile: 'Deep', status: 'completed', findings: 3, risk: 45, duration: '12m 34s', completed: '10 min ago' },
    { id: 'SCN-002', target: 'data-analyst-agent', profile: 'Standard', status: 'running', findings: 1, risk: null, duration: '5m 12s', completed: null, progress: 65 },
    { id: 'SCN-003', target: 'task-automation-agent', profile: 'Quick', status: 'completed', findings: 5, risk: 72, duration: '3m 45s', completed: '1 hr ago' },
    { id: 'SCN-004', target: 'search-assistant', profile: 'Compliance', status: 'scheduled', findings: 0, risk: null, duration: null, completed: null, scheduled: 'in 2 hours' },
    { id: 'SCN-005', target: 'finance-bot', profile: 'Deep', status: 'completed', findings: 0, risk: 12, duration: '15m 22s', completed: '3 hr ago' },
  ];
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Scans</h1>
          <p className="text-gray-500 text-sm mt-1">Vulnerability scanning for AI agents</p>
        </div>
        <Button variant="primary" onClick={() => setShowNewScan(true)}>
          <Search className="w-4 h-4" />
          New Scan
        </Button>
      </div>
      
      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="text-sm text-gray-500">Total Scans</div>
          <div className="text-2xl font-bold text-white font-mono mt-1">156</div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-gray-500">In Progress</div>
          <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">
            {scans.filter(s => s.status === 'running').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-gray-500">Scheduled</div>
          <div className="text-2xl font-bold text-violet-400 font-mono mt-1">
            {scans.filter(s => s.status === 'scheduled').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-gray-500">Avg Risk Score</div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">34</div>
        </Card>
      </div>
      
      {/* Scans List */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Scan ID</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Target</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Profile</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Findings</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Risk</th>
                <th className="text-left py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Duration</th>
                <th className="text-right py-4 px-6 text-sm font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {scans.map(scan => (
                <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-4 px-6 font-mono text-cyan-400">{scan.id}</td>
                  <td className="py-4 px-6 font-medium text-white">{scan.target}</td>
                  <td className="py-4 px-6">
                    <Badge variant="info">{scan.profile}</Badge>
                  </td>
                  <td className="py-4 px-6">
                    {scan.status === 'running' ? (
                      <div className="flex items-center gap-2">
                        <div className="w-20">
                          <ProgressBar value={scan.progress} variant="gradient" size="sm" />
                        </div>
                        <span className="text-sm text-cyan-400">{scan.progress}%</span>
                      </div>
                    ) : (
                      <Badge variant={
                        scan.status === 'completed' ? 'success' :
                        scan.status === 'scheduled' ? 'info' : 'default'
                      }>{scan.status}</Badge>
                    )}
                  </td>
                  <td className="py-4 px-6">
                    {scan.findings > 0 ? (
                      <Badge variant={scan.findings >= 3 ? 'warning' : 'default'}>{scan.findings}</Badge>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="py-4 px-6">
                    {scan.risk !== null ? (
                      <span className={`font-mono ${
                        scan.risk >= 60 ? 'text-red-400' :
                        scan.risk >= 40 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>{scan.risk}%</span>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="py-4 px-6 text-gray-400 font-mono">
                    {scan.duration || scan.scheduled || '-'}
                  </td>
                  <td className="py-4 px-6 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {scan.status === 'completed' && (
                        <Button variant="ghost" size="sm">
                          <FileText className="w-4 h-4" />
                          Report
                        </Button>
                      )}
                      {scan.status === 'running' && (
                        <Button variant="danger" size="sm">
                          <Square className="w-4 h-4" />
                          Stop
                        </Button>
                      )}
                      <IconButton icon={MoreVertical} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

// =============================================================================
// SETTINGS VIEW
// =============================================================================

const SettingsView = () => {
  const [activeTab, setActiveTab] = useState('general');
  
  const tabs = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'integrations', label: 'Integrations', icon: Layers },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'api', label: 'API Keys', icon: Terminal },
  ];
  
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-500 text-sm mt-1">Configure your VerityFlux deployment</p>
      </div>
      
      <div className="flex gap-6">
        {/* Sidebar */}
        <Card className="w-64 p-2 h-fit">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyan-500/10 text-cyan-400'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`}
            >
              <tab.icon className="w-5 h-5" />
              {tab.label}
            </button>
          ))}
        </Card>
        
        {/* Content */}
        <Card className="flex-1 p-6">
          {activeTab === 'general' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">General Settings</h2>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Organization Name</label>
                  <input
                    type="text"
                    defaultValue="Acme Corp"
                    className="w-full px-4 py-2 bg-gray-900 border border-white/[0.06] rounded-lg text-white focus:outline-none focus:border-cyan-500/50"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Deployment Mode</label>
                  <div className="flex items-center gap-4">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input type="radio" name="mode" defaultChecked className="text-cyan-500" />
                      <span className="text-white">Air-Gapped</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input type="radio" name="mode" className="text-cyan-500" />
                      <span className="text-white">Connected</span>
                    </label>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Timezone</label>
                  <select className="w-full px-4 py-2 bg-gray-900 border border-white/[0.06] rounded-lg text-white focus:outline-none focus:border-cyan-500/50">
                    <option>UTC</option>
                    <option>America/New_York</option>
                    <option>America/Los_Angeles</option>
                    <option>Europe/London</option>
                  </select>
                </div>
              </div>
              
              <div className="pt-4 border-t border-white/[0.06]">
                <Button variant="primary">Save Changes</Button>
              </div>
            </div>
          )}
          
          {activeTab === 'security' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Security Settings</h2>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-gray-900/50 rounded-lg">
                  <div>
                    <div className="font-medium text-white">Auto-Approve Low Risk</div>
                    <div className="text-sm text-gray-500">Automatically approve actions below risk threshold</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-sm text-gray-400">Below</span>
                    <input
                      type="number"
                      defaultValue="30"
                      className="w-20 px-3 py-1 bg-gray-800 border border-white/[0.06] rounded text-white text-center"
                    />
                    <span className="text-sm text-gray-400">%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between p-4 bg-gray-900/50 rounded-lg">
                  <div>
                    <div className="font-medium text-white">Auto-Deny High Risk</div>
                    <div className="text-sm text-gray-500">Automatically deny actions above risk threshold</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-sm text-gray-400">Above</span>
                    <input
                      type="number"
                      defaultValue="95"
                      className="w-20 px-3 py-1 bg-gray-800 border border-white/[0.06] rounded text-white text-center"
                    />
                    <span className="text-sm text-gray-400">%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between p-4 bg-gray-900/50 rounded-lg">
                  <div>
                    <div className="font-medium text-white">Approval Timeout</div>
                    <div className="text-sm text-gray-500">Default timeout for approval requests</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <input
                      type="number"
                      defaultValue="30"
                      className="w-20 px-3 py-1 bg-gray-800 border border-white/[0.06] rounded text-white text-center"
                    />
                    <span className="text-sm text-gray-400">minutes</span>
                  </div>
                </div>
              </div>
              
              <div className="pt-4 border-t border-white/[0.06]">
                <Button variant="primary">Save Changes</Button>
              </div>
            </div>
          )}
          
          {activeTab === 'api' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-white">API Keys</h2>
                <Button variant="primary" size="sm">
                  <Terminal className="w-4 h-4" />
                  Generate Key
                </Button>
              </div>
              
              <div className="space-y-3">
                {[
                  { name: 'Production API Key', prefix: 'vf_prod_', created: '2025-01-15', lastUsed: '2 min ago' },
                  { name: 'Development Key', prefix: 'vf_dev_', created: '2025-01-10', lastUsed: '1 day ago' },
                  { name: 'CI/CD Integration', prefix: 'vf_ci_', created: '2025-01-05', lastUsed: '3 hr ago' },
                ].map((key, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 bg-gray-900/50 rounded-lg">
                    <div>
                      <div className="font-medium text-white">{key.name}</div>
                      <div className="text-sm text-gray-500 font-mono">{key.prefix}••••••••</div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right text-sm">
                        <div className="text-gray-400">Created: {key.created}</div>
                        <div className="text-gray-500">Last used: {key.lastUsed}</div>
                      </div>
                      <div className="flex items-center gap-1">
                        <IconButton icon={Copy} />
                        <IconButton icon={X} variant="danger" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {activeTab === 'integrations' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Integrations</h2>
              <p className="text-sm text-gray-500">Note: External integrations are limited in air-gapped mode</p>
              
              <div className="grid grid-cols-2 gap-4">
                {[
                  { name: 'Slack', icon: '💬', status: 'disabled', desc: 'Send alerts to Slack channels' },
                  { name: 'PagerDuty', icon: '🚨', status: 'disabled', desc: 'Incident escalation' },
                  { name: 'Jira', icon: '📋', status: 'disabled', desc: 'Create tickets automatically' },
                  { name: 'Webhook', icon: '🔗', status: 'enabled', desc: 'Custom HTTP webhooks' },
                ].map((int, idx) => (
                  <Card key={idx} className="p-4" hover>
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="text-2xl">{int.icon}</div>
                        <div>
                          <div className="font-medium text-white">{int.name}</div>
                          <div className="text-sm text-gray-500">{int.desc}</div>
                        </div>
                      </div>
                      <Badge variant={int.status === 'enabled' ? 'success' : 'default'}>
                        {int.status}
                      </Badge>
                    </div>
                  </Card>
                ))}
              </div>
            </div>
          )}
          
          {activeTab === 'notifications' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Notification Preferences</h2>
              
              <div className="space-y-3">
                {[
                  { label: 'Critical Alerts', desc: 'Immediate notification for critical security events' },
                  { label: 'Approval Requests', desc: 'Notify when new approvals are waiting' },
                  { label: 'Scan Completion', desc: 'Notify when security scans complete' },
                  { label: 'Daily Summary', desc: 'Daily digest of security events' },
                ].map((pref, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 bg-gray-900/50 rounded-lg">
                    <div>
                      <div className="font-medium text-white">{pref.label}</div>
                      <div className="text-sm text-gray-500">{pref.desc}</div>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" defaultChecked={idx < 2} className="sr-only peer" />
                      <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

// =============================================================================
// MAIN APPLICATION
// =============================================================================

const VerityFluxDashboard = () => {
  const [activeView, setActiveView] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  
  const renderView = () => {
    switch (activeView) {
      case 'dashboard': return <DashboardView />;
      case 'agents': return <AgentsView />;
      case 'approvals': return <ApprovalsView />;
      case 'alerts': return <AlertsView />;
      case 'incidents': return <IncidentsView />;
      case 'scans': return <ScansView />;
      case 'events': return <EventLogView />;
      case 'vulnerabilities': return <VulnerabilitiesView />;
      case 'settings': return <SettingsView />;
      default: return <DashboardView />;
    }
  };
  
  return (
    <div className="min-h-screen bg-[#0a0e17] text-gray-200">
      {/* Background Effects */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-cyan-500/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-violet-500/5 rounded-full blur-[100px]" />
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSAwIDEwIEwgNDAgMTAgTSAxMCAwIEwgMTAgNDAgTSAwIDIwIEwgNDAgMjAgTSAyMCAwIEwgMjAgNDAgTSAwIDMwIEwgNDAgMzAgTSAzMCAwIEwgMzAgNDAiIGZpbGw9Im5vbmUiIHN0cm9rZT0icmdiYSgyNTUsMjU1LDI1NSwwLjAyKSIgc3Ryb2tlLXdpZHRoPSIxIi8+PC9wYXR0ZXJuPjwvZGVmcz48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSJ1cmwoI2dyaWQpIi8+PC9zdmc+')] opacity-50" />
      </div>
      
      {/* Sidebar */}
      <Sidebar 
        activeView={activeView} 
        setActiveView={setActiveView}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
      />
      
      {/* Main Content */}
      <div className={`transition-all duration-300 ${sidebarCollapsed ? 'ml-16' : 'ml-64'}`}>
        <Header threatLevel={mockMetrics.threatLevel} />
        <main className="p-6">
          {renderView()}
        </main>
      </div>
      
      {/* Global Styles */}
      <style jsx global>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        
        * {
          scrollbar-width: thin;
          scrollbar-color: rgba(255,255,255,0.1) transparent;
        }
        
        ::-webkit-scrollbar {
          width: 6px;
          height: 6px;
        }
        
        ::-webkit-scrollbar-track {
          background: transparent;
        }
        
        ::-webkit-scrollbar-thumb {
          background: rgba(255,255,255,0.1);
          border-radius: 3px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
          background: rgba(255,255,255,0.2);
        }
        
        body {
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        
        code, .font-mono {
          font-family: 'JetBrains Mono', 'Fira Code', monospace;
        }
        
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        
        .animate-pulse {
          animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        
        @keyframes ping {
          75%, 100% {
            transform: scale(2);
            opacity: 0;
          }
        }
        
        .animate-ping {
          animation: ping 1s cubic-bezier(0, 0, 0.2, 1) infinite;
        }
      `}</style>
    </div>
  );
};

export default VerityFluxDashboard;
