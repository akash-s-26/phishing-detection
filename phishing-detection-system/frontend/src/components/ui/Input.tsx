import { type InputHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/utils/cn';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'w-full rounded-[8px_12px_10px_14px] border border-slate-500/30 bg-black/20 px-4 py-2.5 text-sm text-current placeholder:text-slate-400 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/30',
        className
      )}
      {...props}
    />
  )
);
Input.displayName = 'Input';
