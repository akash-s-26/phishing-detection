import { Link } from 'react-router-dom';
import { ShieldQuestion } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="mx-auto flex min-h-[70vh] max-w-md flex-col items-center justify-center gap-3 px-6 text-center">
      <ShieldQuestion className="h-10 w-10 text-slate-500" />
      <h1 className="font-hand text-3xl underline-scribble">Page not found</h1>
      <p className="text-sm text-slate-400">This page doesn't exist — maybe it redirected somewhere phishy.</p>
      <Link to="/" className="text-brand-soft hover:underline">
        Back to Scan
      </Link>
    </div>
  );
}
