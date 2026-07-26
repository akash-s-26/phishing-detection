import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/utils/cn';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'danger';
  isLoading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', isLoading, disabled, children, ...props }, ref) => {
    const base =
      'inline-flex items-center justify-center gap-2 rounded-[10px_14px_12px_16px] px-5 py-2.5 font-medium text-sm transition-all duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.98]';

    const variants: Record<string, string> = {
      primary: 'bg-brand text-white shadow-[0_4px_14px_-4px_rgba(91,141,239,0.6)] hover:bg-brand-soft',
      ghost: 'bg-transparent border border-slate-500/30 text-slate-200 hover:bg-slate-500/10',
      danger: 'bg-danger text-white hover:brightness-110',
    };

    return (
      <button ref={ref} className={cn(base, variants[variant], className)} disabled={disabled || isLoading} {...props}>
        {isLoading && (
          <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
        )}
        {children}
      </button>
    );
  }
);
Button.displayName = 'Button';
