import { motion } from 'framer-motion';
import { verdictHex } from '@/utils/cn';

interface RiskRingProps {
  score: number; // 0-100
  verdict: string;
  size?: number;
}

/**
 * A hand-sketched circular meter — deliberately imperfect (a slightly
 * wobbly path instead of a perfect <circle>) so it reads as "drawn" rather
 * than "rendered". Draws itself in with a stroke-dashoffset animation.
 */
export function RiskRing({ score, verdict, size = 160 }: RiskRingProps) {
  const radius = size / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = verdictHex(verdict);
  const cx = size / 2;
  const cy = size / 2;

  // A slightly irregular circle path (hand-drawn wobble) built from noisy points.
  const points = 40;
  const wobble = 2.4;
  let path = '';
  for (let i = 0; i <= points; i++) {
    const angle = (i / points) * Math.PI * 2 - Math.PI / 2;
    const r = radius + Math.sin(i * 3.1) * wobble + Math.cos(i * 1.7) * (wobble / 2);
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    path += i === 0 ? `M ${x} ${y} ` : `L ${x} ${y} `;
  }
  path += 'Z';

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <path d={path} fill="none" stroke="currentColor" strokeOpacity={0.12} strokeWidth={9} />
        <motion.path
          d={path}
          fill="none"
          stroke={color}
          strokeWidth={9}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.1, ease: 'easeOut' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="font-mono text-3xl font-semibold"
          style={{ color }}
        >
          {Math.round(score)}
        </motion.span>
        <span className="text-[11px] uppercase tracking-widest text-slate-400">risk score</span>
      </div>
    </div>
  );
}
