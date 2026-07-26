import { AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/Button';

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
}

export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div className="sketch-panel flex flex-col items-center gap-3 p-8 text-center">
      <AlertTriangle className="h-8 w-8 text-danger" />
      <p className="max-w-sm text-sm text-slate-300">{message}</p>
      {onRetry && (
        <Button variant="ghost" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}
