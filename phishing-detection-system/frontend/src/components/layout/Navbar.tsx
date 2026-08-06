import { NavLink, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, LogOut, Activity, LayoutDashboard, History, BarChart3 } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/utils/cn';

const LINKS = [
  { to: '/', label: 'Scan', icon: Activity },
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/history', label: 'History', icon: History },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
];

export function Navbar() {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  return (
    <header className="sticky top-0 z-40 border-b border-white/10 bg-[#090d16]/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3.5">
        <NavLink to="/" className="flex items-center gap-3 group">
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 shadow-[0_0_15px_rgba(56,189,248,0.15)] group-hover:border-cyan-400/50"
          >
            <Shield className="h-5 w-5" />
          </motion.div>
          <div>
            <span className="font-bold text-lg tracking-wide text-white flex items-center gap-1.5">
              PhishGuard <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono font-semibold">AI</span>
            </span>
          </div>
        </NavLink>

        <nav className="hidden items-center gap-1 md:flex bg-slate-900/60 border border-white/5 rounded-full p-1">
          {LINKS.map((link) => {
            const Icon = link.icon;
            return (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.to === '/'}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-2 rounded-full px-4 py-1.5 text-xs font-semibold transition-all',
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                  )
                }
              >
                <Icon className="h-3.5 w-3.5" />
                {link.label}
              </NavLink>
            );
          })}
        </nav>

        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <div className="flex items-center gap-3">
              <NavLink
                to="/profile"
                className="hidden text-xs font-medium text-slate-300 hover:text-white sm:block bg-slate-800/50 border border-white/5 px-3 py-1.5 rounded-full"
              >
                {user?.name}
              </NavLink>
              <button
                onClick={handleLogout}
                aria-label="Log out"
                className="flex items-center gap-1.5 rounded-full border border-rose-500/20 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-400 transition hover:bg-rose-500/20"
              >
                <LogOut className="h-3.5 w-3.5" />
                Logout
              </button>
            </div>
          ) : (
            <NavLink
              to="/login"
              className="rounded-full bg-cyan-500/10 border border-cyan-500/30 px-5 py-1.5 text-xs font-bold text-cyan-400 transition hover:bg-cyan-500/20 hover:border-cyan-400"
            >
              Log In
            </NavLink>
          )}
        </div>
      </div>

      <nav className="flex items-center gap-1 overflow-x-auto border-t border-white/5 px-4 py-2 md:hidden bg-slate-950/40">
        {LINKS.map((link) => {
          const Icon = link.icon;
          return (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-1.5 shrink-0 rounded-full px-3 py-1 text-xs font-medium',
                  isActive ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30' : 'text-slate-400'
                )
              }
            >
              <Icon className="h-3 w-3" />
              {link.label}
            </NavLink>
          );
        })}
      </nav>
    </header>
  );
}
