import { NavLink, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Sun, Moon, LogOut, ShieldHalf } from 'lucide-react';
import { useTheme } from '@/hooks/useTheme';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/utils/cn';

const LINKS = [
  { to: '/', label: 'Scan' },
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/history', label: 'History' },
  { to: '/analytics', label: 'Analytics' },
];

export function Navbar() {
  const { theme, toggleTheme } = useTheme();
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  return (
    <header className="sticky top-0 z-40 border-b border-slate-500/15 bg-ink/70 backdrop-blur-lg">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
        <NavLink to="/" className="flex items-center gap-2">
          <motion.div whileHover={{ rotate: -6 }} className="rounded-full bg-brand/15 p-1.5 text-brand-soft">
            <ShieldHalf className="h-5 w-5" />
          </motion.div>
          <span className="font-hand text-xl underline-scribble">PhishShield</span>
        </NavLink>

        <nav className="hidden items-center gap-1 md:flex">
          {LINKS.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === '/'}
              className={({ isActive }) =>
                cn(
                  'rounded-full px-4 py-1.5 text-sm transition',
                  isActive ? 'bg-brand/15 text-brand-soft' : 'text-slate-400 hover:text-slate-200'
                )
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <button
            onClick={toggleTheme}
            aria-label="Toggle theme"
            className="rounded-full p-2 text-slate-400 transition hover:bg-slate-500/10 hover:text-slate-200"
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>

          {isAuthenticated ? (
            <div className="flex items-center gap-2">
              <NavLink
                to="/profile"
                className="hidden text-sm text-slate-300 hover:text-slate-100 sm:block"
              >
                {user?.name}
              </NavLink>
              <button
                onClick={handleLogout}
                aria-label="Log out"
                className="rounded-full p-2 text-slate-400 transition hover:bg-danger/10 hover:text-danger"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <NavLink
              to="/login"
              className="rounded-full bg-brand px-4 py-1.5 text-sm font-medium text-white hover:bg-brand-soft"
            >
              Log in
            </NavLink>
          )}
        </div>
      </div>

      <nav className="flex items-center gap-1 overflow-x-auto border-t border-slate-500/10 px-4 py-2 md:hidden">
        {LINKS.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === '/'}
            className={({ isActive }) =>
              cn(
                'shrink-0 rounded-full px-3 py-1 text-xs',
                isActive ? 'bg-brand/15 text-brand-soft' : 'text-slate-400'
              )
            }
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}
