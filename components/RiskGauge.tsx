"use client";

interface Props {
  score: number;
  rating: string;
}

export default function RiskGauge({ score, rating }: Props) {
  const radius = 70;
  const circumference = Math.PI * radius; // half circle
  const progress = (score / 100) * circumference;

  const color =
    score >= 80 ? "#4FD1C5" : score >= 50 ? "#F2A93B" : "#E5484D";

  return (
    <div className="flex flex-col items-center">
      <svg width="180" height="100" viewBox="0 0 180 100">
        <path
          d="M 20 90 A 70 70 0 0 1 160 90"
          fill="none"
          stroke="#1E2A38"
          strokeWidth="14"
          strokeLinecap="round"
        />
        <path
          d="M 20 90 A 70 70 0 0 1 160 90"
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: "stroke-dasharray 0.8s ease" }}
        />
        <text
          x="90"
          y="75"
          textAnchor="middle"
          className="font-display"
          fontSize="32"
          fontWeight="700"
          fill="#E8EDF2"
        >
          {score}
        </text>
      </svg>
      <div className="text-xs tracking-widest uppercase mt-1" style={{ color }}>
        {rating}
      </div>
    </div>
  );
}
