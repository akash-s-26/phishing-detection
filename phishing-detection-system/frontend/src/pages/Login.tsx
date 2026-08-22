import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';

import { toast } from 'sonner';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { useAuth } from '@/hooks/useAuth';
import { getApiErrorMessage } from '@/services/api';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await login(email, password);
      toast.success('Welcome back.');
      navigate('/dashboard');
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[80vh] max-w-md flex-col justify-center px-6">
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <img src="/icon.png" alt="PhishGuard Logo" className="h-10 w-10 object-contain mb-1" />
          <h1 className="font-hand text-3xl underline-scribble">Welcome back</h1>
          <p className="text-sm text-slate-400">Log in to see your scan history and analytics.</p>
        </div>

        <Card>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div>
              <label className="mb-1.5 block text-xs text-slate-400">Email</label>
              <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
            </div>
            <div>
              <label className="mb-1.5 block text-xs text-slate-400">Password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
            </div>
            {error && <p className="text-sm text-danger">{error}</p>}
            <Button type="submit" isLoading={isLoading} className="w-full">
              Log in
            </Button>
          </form>
        </Card>

        <p className="mt-4 text-center text-sm text-slate-400">
          No account yet?{' '}
          <Link to="/signup" className="text-brand-soft hover:underline">
            Sign up
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
