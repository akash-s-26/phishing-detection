import { UserCircle2, Mail, CalendarDays } from 'lucide-react';
import { Card } from '@/components/ui/Card';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { useAsync } from '@/hooks/useAsync';
import { fetchProfile } from '@/services/authService';
import { formatDate } from '@/utils/cn';

export default function Profile() {
  const profile = useAsync(fetchProfile);

  return (
    <div className="mx-auto max-w-2xl px-6 py-10">
      <h1 className="mb-6 font-hand text-4xl underline-scribble">Your profile</h1>

      {profile.isLoading && <Skeleton className="h-48" />}
      {!profile.isLoading && profile.error && <ErrorState message={profile.error} onRetry={profile.refetch} />}
      {!profile.isLoading && profile.data && (
        <Card className="flex flex-col gap-4">
          <div className="flex items-center gap-4">
            <div className="rounded-full bg-brand/15 p-4 text-brand-soft">
              <UserCircle2 className="h-8 w-8" />
            </div>
            <div>
              <p className="font-hand text-2xl">{profile.data.name}</p>
              <p className="text-sm text-slate-400">PhishShield member</p>
            </div>
          </div>

          <div className="grid gap-3 border-t border-slate-500/15 pt-4 text-sm">
            <div className="flex items-center gap-2 text-slate-300">
              <Mail className="h-4 w-4 text-slate-500" />
              {profile.data.email}
            </div>
            {profile.data.created_at && (
              <div className="flex items-center gap-2 text-slate-300">
                <CalendarDays className="h-4 w-4 text-slate-500" />
                Joined {formatDate(profile.data.created_at)}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
